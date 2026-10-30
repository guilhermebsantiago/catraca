package store

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
)

// batchScript runs the operations of one scriptCall, in order. KEYS lists
// each key once. ARGV starts with the call's Dedupe key, by its index in
// KEYS, and that key's ttl, or 0 and 0 without one; then come the
// operations, each an opcode followed by its arguments, keys being given by
// their index in KEYS:
//
//	I key bucket delta ttl            counter: add delta to bucket
//	C key bucket                      counter: count over the window ending in bucket
//	A bucketkey blockkey member ttl   distinct: add member to its bucket and block
//	D n key...                        distinct: count the union of n HyperLogLogs
//	M key member ms cutoff ttl        seen: mark member at ms, forget those <= cutoff
//	S key member                      seen: the member's score, or nil
//	F key ms ttl                      first seen: keep the smaller of ms and the record
//	V key value ttl                   value: set
//	G key                             value: get, or nil
//	X key                             value: delete
//
// It returns the result of each C, D, S, F and G, in order, then 1 when the
// Dedupe key existed, so the I operations were skipped, and 0 otherwise. A
// ttl of 0 means none.
//
// The Dedupe key is set, with NX, before any operation runs. An error that
// stops the script midway, such as a counter holding something that is not
// a number, leaves the writes made before it, the key included: sending the
// batch again then skips the increments that did not apply rather than
// repeat those that did, since a count too low costs detection and a count
// too high can block a good sender. Out of memory stops the script at its
// first write, the key's, before anything applies.
//
// A counter hash holds a field per bucket, n (its newest bucket) and s (the
// sum of its buckets). Buckets are kept only within the window of the newest
// one, so s is the count over that window. The script caches what it reads
// of each counter, so a count after an increment of the same counter, the
// catalog's usual order, costs no call, and an increment costs one read and
// one write besides the expiry. Counts are Lua numbers, exact up to 2^53.
//
// Numbers the script computes are formatted with %d before they reach Redis:
// the conversion redis.call applies to a Lua number has changed between
// Redis versions, and some print 1000000000 as "1e+09".
var batchScript = strings.ReplaceAll(`
local B = BUCKETS
local call, tonumber = redis.call, tonumber
local keys, argv = KEYS, ARGV
local out = {}

local function str(x)
  return string.format('%d', x)
end

local function num(k, v)
  local x = tonumber(v)
  if not x then
    error('counter ' .. k .. ' holds "' .. tostring(v) .. '"')
  end
  return x
end

-- counters caches each counter this run has touched: {newest bucket, sum,
-- {field = bucket value}}, or false when the counter does not exist.
local counters = {}

-- load returns the cached state of counter k, reading n, s and, when given,
-- one bucket field on first use.
local function load(k, field)
  local c = counters[k]
  if c == nil then
    local m
    if field then
      m = call('HMGET', k, 'n', 's', field)
    else
      m = call('HMGET', k, 'n', 's')
    end
    c = false
    if m[1] then
      c = {num(k, m[1]), num(k, m[2] or 0), {}}
      if field then
        c[3][field] = m[3] and num(k, m[3]) or 0
      end
    end
    counters[k] = c
  end
  return c
end

-- sum returns the sum of buckets lo..hi of counter k, and their field names.
local function sum(k, lo, hi)
  local f = {}
  for b = lo, hi do
    f[#f + 1] = str(b)
  end
  local v = call('HMGET', k, unpack(f))
  local s = 0
  for j = 1, #f do
    if v[j] then
      s = s + num(k, v[j])
    end
  end
  return s, f
end

local function incr(k, field, delta, ttl)
  local idx = tonumber(field)
  local c = load(k, field)
  if c and idx <= c[1] - B then
    -- No window ending in the newest bucket or later can read it.
    return
  end
  if c and idx - B >= c[1] then
    -- Every stored bucket leaves the window.
    call('DEL', k)
    c = false
  end
  local moved = true
  if not c then
    c = {idx, 0, {[field] = 0}}
    counters[k] = c
  elseif idx > c[1] then
    local gone, f = sum(k, c[1] - B + 1, idx - B)
    call('HDEL', k, unpack(f))
    for j = 1, #f do
      c[3][f[j]] = nil
    end
    c[1], c[2] = idx, c[2] - gone
  else
    moved = false
  end
  local v = c[3][field]
  if v == nil then
    v = num(k, call('HGET', k, field) or 0)
  end
  v = v + tonumber(delta)
  c[2] = c[2] + tonumber(delta)
  c[3][field] = v
  if moved then
    call('HSET', k, field, str(v), 's', str(c[2]), 'n', field)
  else
    call('HSET', k, field, str(v), 's', str(c[2]))
  end
  call('PEXPIRE', k, ttl)
end

local function count(k, idx)
  local c = load(k)
  if not c then
    return 0
  end
  local newest, s = c[1], c[2]
  if idx == newest then
    return s
  end
  if idx > newest then
    if idx - B >= newest then
      return 0
    end
    -- The stored buckets up to idx - B have left this window.
    return s - (sum(k, newest - B + 1, idx - B))
  end
  -- A window ending before the newest bucket: add up the stored buckets in it.
  if idx < newest - B + 1 then
    return 0
  end
  return (sum(k, newest - B + 1, idx))
end

-- repeated is true when the call's Dedupe key exists: a call with the same
-- id applied these increments already.
local repeated = false
if argv[1] ~= '0' then
  repeated = not call('SET', keys[tonumber(argv[1])], '1', 'NX', 'PX', argv[2])
end

local i, n = 3, #argv
while i <= n do
  local op = argv[i]
  if op == 'D' then
    local c, ks = tonumber(argv[i + 1]), {}
    for j = 1, c do
      ks[j] = keys[tonumber(argv[i + 1 + j])]
    end
    out[#out + 1] = call('PFCOUNT', unpack(ks))
    i = i + 2 + c
  else
    local k = keys[tonumber(argv[i + 1])]
    if op == 'C' then
      out[#out + 1] = count(k, tonumber(argv[i + 2]))
      i = i + 3
    elseif op == 'I' then
      if not repeated then
        incr(k, argv[i + 2], argv[i + 3], argv[i + 4])
      end
      i = i + 5
    elseif op == 'A' then
      local block, member, ttl = keys[tonumber(argv[i + 2])], argv[i + 3], argv[i + 4]
      call('PFADD', k, member)
      call('PEXPIRE', k, ttl)
      call('PFADD', block, member)
      call('PEXPIRE', block, ttl)
      i = i + 5
    elseif op == 'M' then
      call('ZADD', k, 'GT', argv[i + 3], argv[i + 2])
      call('ZREMRANGEBYSCORE', k, '-inf', argv[i + 4])
      call('PEXPIRE', k, argv[i + 5])
      i = i + 6
    elseif op == 'S' then
      out[#out + 1] = call('ZSCORE', k, argv[i + 2])
      i = i + 3
    elseif op == 'F' then
      call('ZADD', k, 'LT', argv[i + 2], 't')
      if argv[i + 3] == '0' then
        call('PERSIST', k)
      else
        call('PEXPIRE', k, argv[i + 3])
      end
      out[#out + 1] = call('ZSCORE', k, 't')
      i = i + 4
    elseif op == 'V' then
      if argv[i + 3] == '0' then
        call('SET', k, argv[i + 2])
      else
        call('SET', k, argv[i + 2], 'PX', argv[i + 3])
      end
      i = i + 4
    elseif op == 'G' then
      out[#out + 1] = call('GET', k)
      i = i + 2
    elseif op == 'X' then
      call('DEL', k)
      i = i + 2
    else
      error('unknown operation ' .. tostring(op))
    end
  end
end
out[#out + 1] = repeated and 1 or 0
return out
`, "BUCKETS", strconv.Itoa(Buckets))

// batchSHA is the SHA-1 digest EVALSHA names batchScript by.
var batchSHA = func() string {
	sum := sha1.Sum([]byte(batchScript))
	return hex.EncodeToString(sum[:])
}()
