// See LICENSE for license details.

#include "cachesim.h"
#include "common.h"
#include <cstdlib>
#include <iostream>
#include <iomanip>

cache_sim_t::cache_sim_t(size_t _sets, size_t _ways, size_t _linesz, const char* _name)
: sets(_sets), ways(_ways), linesz(_linesz), name(_name), log(false)
{
  init();
}

static void help()
{
  std::cerr << "Cache configurations must be of the form" << std::endl;
  std::cerr << "  sets:ways:blocksize" << std::endl;
  std::cerr << "where sets, ways, and blocksize are positive integers, with" << std::endl;
  std::cerr << "sets and blocksize both powers of two and blocksize at least 8." << std::endl;
  exit(1);
}

cache_sim_t* cache_sim_t::construct(const char* config, const char* name)
{
  const char* wp = strchr(config, ':');
  if (!wp++) help();
  const char* bp = strchr(wp, ':');
  if (!bp++) help();
  const char *type = strchr(bp, ':');
  if(type) type++;

  size_t sets = atoi(std::string(config, wp).c_str());
  size_t ways = atoi(std::string(wp, bp).c_str());
  size_t linesz;
  if(type) {
      linesz = atoi(std::string(bp, type).c_str());
  }
  else {
      linesz = atoi(bp);
  }

  if(type && !strcmp(type, "linear")) 
    return new linear_evict_cache_sim_t(sets, ways, linesz, name);
  if(type && !strcmp(type, "hawkeye")) 
    return new hawkeye_cache_sim_t(sets, ways, linesz, name);
  if (ways > 4 /* empirical */ && sets == 1)
    return new fa_cache_sim_t(ways, linesz, name);
  return new cache_sim_t(sets, ways, linesz, name);
}

void cache_sim_t::init()
{
  if(sets == 0 || (sets & (sets-1)))
    help();
  if(linesz < 8 || (linesz & (linesz-1)))
    help();

  idx_shift = 0;
  for (size_t x = linesz; x>1; x >>= 1)
    idx_shift++;

  tags = new uint64_t[sets*ways]();
  read_accesses = 0;
  read_misses = 0;
  bytes_read = 0;
  write_accesses = 0;
  write_misses = 0;
  bytes_written = 0;
  writebacks = 0;

  miss_handler = NULL;
}

cache_sim_t::cache_sim_t(const cache_sim_t& rhs)
 : sets(rhs.sets), ways(rhs.ways), linesz(rhs.linesz),
   idx_shift(rhs.idx_shift), name(rhs.name), log(false)
{
  tags = new uint64_t[sets*ways];
  memcpy(tags, rhs.tags, sets*ways*sizeof(uint64_t));
}

cache_sim_t::~cache_sim_t()
{
  print_stats();
  delete [] tags;
}

void cache_sim_t::print_stats()
{
  if(read_accesses + write_accesses == 0)
    return;

  float mr = 100.0f*(read_misses+write_misses)/(read_accesses+write_accesses);

  std::cout << std::setprecision(3) << std::fixed;
  std::cout << name << " ";
  std::cout << "Bytes Read:            " << bytes_read << std::endl;
  std::cout << name << " ";
  std::cout << "Bytes Written:         " << bytes_written << std::endl;
  std::cout << name << " ";
  std::cout << "Read Accesses:         " << read_accesses << std::endl;
  std::cout << name << " ";
  std::cout << "Write Accesses:        " << write_accesses << std::endl;
  std::cout << name << " ";
  std::cout << "Read Misses:           " << read_misses << std::endl;
  std::cout << name << " ";
  std::cout << "Write Misses:          " << write_misses << std::endl;
  std::cout << name << " ";
  std::cout << "Writebacks:            " << writebacks << std::endl;
  std::cout << name << " ";
  std::cout << "Miss Rate:             " << mr << '%' << std::endl;
}

uint64_t* cache_sim_t::check_tag(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t tag = (addr >> idx_shift) | VALID;

  for (size_t i = 0; i < ways; i++)
    if (tag == (tags[idx*ways + i] & ~DIRTY))
      return &tags[idx*ways + i];

  return NULL;
}

uint64_t cache_sim_t::victimize(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t way = lfsr.next() % ways;
  uint64_t victim = tags[idx*ways + way];
  tags[idx*ways + way] = (addr >> idx_shift) | VALID;
  return victim;
}

void cache_sim_t::access(uint64_t addr, size_t bytes, bool store)
{
  store ? write_accesses++ : read_accesses++;
  (store ? bytes_written : bytes_read) += bytes;

  uint64_t* hit_way = check_tag(addr);
  if (likely(hit_way != NULL))
  {
    if (store)
      *hit_way |= DIRTY;
    return;
  }

  store ? write_misses++ : read_misses++;
  if (log)
  {
    std::cerr << name << " "
              << (store ? "write" : "read") << " miss 0x"
              << std::hex << addr << std::endl;
  }

  uint64_t victim = victimize(addr);

  if ((victim & (VALID | DIRTY)) == (VALID | DIRTY))
  {
    uint64_t dirty_addr = (victim & ~(VALID | DIRTY)) << idx_shift;
    if (miss_handler)
      miss_handler->access(dirty_addr, linesz, true);
    writebacks++;
  }

  if (miss_handler)
    miss_handler->access(addr & ~(linesz-1), linesz, false);

  if (store)
    *check_tag(addr) |= DIRTY;
}

fa_cache_sim_t::fa_cache_sim_t(size_t ways, size_t linesz, const char* name)
  : cache_sim_t(1, ways, linesz, name)
{
}

uint64_t* fa_cache_sim_t::check_tag(uint64_t addr)
{
  auto it = tags.find(addr >> idx_shift);
  return it == tags.end() ? NULL : &it->second;
}

uint64_t fa_cache_sim_t::victimize(uint64_t addr)
{
  uint64_t old_tag = 0;
  if (tags.size() == ways)
  {
    auto it = tags.begin();
    std::advance(it, lfsr.next() % ways);
    old_tag = it->second;
    tags.erase(it);
  }
  tags[addr >> idx_shift] = (addr >> idx_shift) | VALID;
  return old_tag;
}

hawkeye_cache_sim_t::hawkeye_cache_sim_t(size_t sets, size_t ways, size_t linesz, const char* name):
cache_sim_t(sets, ways, linesz, name), addr_history() {
  rrpv = new uint32_t*[sets];
  for (size_t i = 0; i < sets; i++){
    rrpv[i] = new uint32_t[ways];
  }
  signatures = new uint64_t*[sets];
  for (size_t i = 0; i < sets; i++){
    signatures[i] = new uint64_t[ways];
  }

  perset_optgen = new OPTgen[sets];
  perset_timer = new uint64_t[sets];
  demand_predictor = new HAWKEYE_PC_PREDICTOR();

  addr_history.resize(sets);
  for (size_t i=0; i<sets; i++) 
    addr_history[i].clear();

  for (size_t i=0; i<sets; i++) {
      for (size_t j=0; j<ways; j++) {
          rrpv[i][j] = MAX_RRPV;
          signatures[i][j] = 0;
      }
      perset_timer[i] = 0;
      perset_optgen[i].init(ways-2);
  }

}

uint64_t hawkeye_cache_sim_t::victimize(uint64_t addr) {
  size_t set = (addr >> idx_shift) & (sets-1);
  // look for the MAX_RRPV line
  for (uint32_t i=0; i<ways; i++) {
    if (rrpv[set][i] == MAX_RRPV) {
      uint64_t victim = tags[set*ways + i];
      tags[set*ways + i] = (addr >> idx_shift) | VALID;
      return victim;
    }
  }

  //If we cannot find a cache-averse line, we evict the oldest cache-friendly line
  uint32_t max_rrip = 0;
  int32_t lru_victim = -1;
  for (uint32_t i=0; i<ways; i++)
  {
      if (rrpv[set][i] >= max_rrip)
      {
          max_rrip = rrpv[set][i];
          lru_victim = i;
      }
  }

  uint64_t victim = tags[set*ways + lru_victim];
  tags[set*ways + lru_victim] = (addr >> idx_shift) | VALID;

  // Catch up on updating
  uint64_t PC = proc->get_state()->pc;
  bool new_prediction = demand_predictor->get_prediction (PC);
  int32_t way = lru_victim;
  signatures[set][way] = PC;
  //Set RRIP values and age cache-friendly line
  if(!new_prediction)
      rrpv[set][way] = MAX_RRPV;
  else
  {
      rrpv[set][way] = 0;
      bool saturated = false;
      for(uint32_t i=0; i<ways; i++)
          if (rrpv[set][i] == MAX_RRPV-1)
              saturated = true;

      //Age all the cache-friendly  lines
      for(uint32_t i=0; i<ways; i++)
      {
          if (!saturated && rrpv[set][i] < MAX_RRPV-1)
              rrpv[set][i]++;
      }
      rrpv[set][way] = 0;
  }

  //The predictor is trained negatively on LRU evictions
  demand_predictor->decrement(signatures[set][lru_victim]);

  return victim;
}

void hawkeye_cache_sim_t::replace_addr_history_element(unsigned int sampler_set)
{
    uint64_t lru_addr = 0;
    
    for(map<uint64_t, ADDR_INFO>::iterator it=addr_history[sampler_set].begin(); it != addr_history[sampler_set].end(); it++)
    {
   //     uint64_t timer = (it->second).last_quanta;

        if((it->second).lru == (ways-1))
        {
            //lru_time =  (it->second).last_quanta;
            lru_addr = it->first;
            break;
        }
    }

    addr_history[sampler_set].erase(lru_addr);
}

void hawkeye_cache_sim_t::update_addr_history_lru(unsigned int sampler_set, unsigned int curr_lru)
{
    for(map<uint64_t, ADDR_INFO>::iterator it=addr_history[sampler_set].begin(); it != addr_history[sampler_set].end(); it++)
    {
        if((it->second).lru < curr_lru)
        {
            (it->second).lru++;
        }
    }
}


uint64_t* hawkeye_cache_sim_t::check_tag(uint64_t addr) {
  size_t set = (addr >> idx_shift) & (sets-1);
  uint64_t PC = proc->get_state()->pc;
  
  //The current timestep 
  uint64_t curr_quanta = perset_timer[set] % OPTGEN_VECTOR_SIZE;

  uint32_t sampler_set = (addr >> idx_shift) & (sets-1);
  uint64_t sampler_tag = (addr >> idx_shift) | VALID;

  // This line has been used before. Since the right end of a usage interval is always 
  //a demand, ignore prefetches
  if (addr_history[sampler_set].find(sampler_tag) != addr_history[sampler_set].end())
  {
      unsigned int curr_timer = perset_timer[set];
      if(curr_timer < addr_history[sampler_set][sampler_tag].last_quanta)
         curr_timer = curr_timer + TIMER_SIZE;
      bool wrap =  ((curr_timer - addr_history[sampler_set][sampler_tag].last_quanta) > OPTGEN_VECTOR_SIZE);
      uint64_t last_quanta = addr_history[sampler_set][sampler_tag].last_quanta % OPTGEN_VECTOR_SIZE;
      //and for prefetch hits, we train the last prefetch trigger PC
      if( !wrap && perset_optgen[set].should_cache(curr_quanta, last_quanta))
      {
        demand_predictor->increment(addr_history[sampler_set][sampler_tag].PC);
      }
      else
      {
        demand_predictor->decrement(addr_history[sampler_set][sampler_tag].PC);
      }
      //Some maintenance operations for OPTgen
      perset_optgen[set].add_access(curr_quanta);
      update_addr_history_lru(sampler_set, addr_history[sampler_set][sampler_tag].lru);
  }
  // This is the first time we are seeing this line (could be demand or prefetch)
  else if(addr_history[sampler_set].find(sampler_tag) == addr_history[sampler_set].end())
  {
      // Find a victim from the sampled cache if we are sampling
      if(addr_history[sampler_set].size() == ways) 
          replace_addr_history_element(sampler_set);

      //Initialize a new entry in the sampler
      addr_history[sampler_set][sampler_tag].init(curr_quanta);
      
      perset_optgen[set].add_access(curr_quanta);
      update_addr_history_lru(sampler_set, ways-1);
  }
  
  // Get Hawkeye's prediction for this line
  bool new_prediction = demand_predictor->get_prediction (PC);
  // Update the sampler with the timestamp, PC and our prediction
  // For prefetches, the PC will represent the trigger PC
  addr_history[sampler_set][sampler_tag].update(perset_timer[set], PC, new_prediction);
  addr_history[sampler_set][sampler_tag].lru = 0;
  //Increment the set timer
  perset_timer[set] = (perset_timer[set]+1) % TIMER_SIZE;

  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t tag = (addr >> idx_shift) | VALID;
  int way = -1;

  for (size_t i = 0; i < ways; i++)
    if (tag == (tags[idx*ways + i] & ~DIRTY)) {
      way = i;
    }

  // If way is -1, do this in the evict stage instead
  if (way != -1) {
    signatures[set][way] = PC;

    //Set RRIP values and age cache-friendly line
    if(!new_prediction)
        rrpv[set][way] = MAX_RRPV;
    else
    {
        rrpv[set][way] = 0;
    }
  }

  return cache_sim_t::check_tag(addr);
}

linear_evict_cache_sim_t::linear_evict_cache_sim_t(size_t sets,
    size_t ways, size_t linesz, const char* name)
  : cache_sim_t(sets, ways, linesz, name), evict_candidate()
{
    std::cout << "Linear Evict Cache Simulator" << std::endl;
}

uint64_t linear_evict_cache_sim_t::victimize(uint64_t addr)
{
  size_t idx = (addr >> idx_shift) & (sets-1);
  size_t way = evict_candidate[idx];
  evict_candidate[idx] = (evict_candidate[idx] + 1) % ways;
  uint64_t victim = tags[idx*ways + way];
  tags[idx*ways + way] = (addr >> idx_shift) | VALID;
  return victim;
}
