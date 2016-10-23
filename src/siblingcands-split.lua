#!/usr/bin/lua

--[[
Input: CSV-style sibling candidates, unique
1.2.3.4,1:2::3:4
4.5.6.7,4:5::6:7
Output: Defined chunks with n IPs to measure,
created as new files
]]--

-- pattern to match IP,IP
local pattern = "([^,]+),([^,]+)"

local ips6 = {}
local ips4 = {}

local infile, n = ...
if not infile  or not n then
  print("usage: file.lua infile #ips-per-file")
return
end
--infh=assert(io.open(infile,'r'))
count=0
local linesread=0
local linesreadtot=0
count4=0
count6=0
once=0
n=assert(tonumber(n))
outfd=assert(io.open(infile..".pairs."..n.."."..string.format("%02.2d",count),'w'))

for line in io.lines(infile) do
  local ip4,ip6 = line:match(pattern)
  linesread = linesread + 1
  linesreadtot = linesreadtot+1
  if(ip4 ~= nil and ip6 ~= nil) then
    outfd:write(ip4,",",ip6,"\n")
    if(linesread*2<=n) then -- proceed efficiently while ips < n for sure
      ips6[ip6] = 1
      ips4[ip4] = 1
    end
    if(linesread*2>n) then -- proceed carefully when ips can become > n
      if(once==0) then
        count4,count6=0,0
        for _ in pairs(ips4) do count4 = count4 + 1 end
        for _ in pairs(ips6) do count6 = count6 + 1 end
        once=1
      end
      if(ips6[ip6] == nil) then
        count6=count6+1
      end
      if(ips4[ip4] == nil) then
        count4=count4+1
      end
      ips6[ip6] = 1
      ips4[ip4] = 1

      if((count4+count6) > n) then
        ips=0
        count4=0
        count6=0
        once=0
        linesread=0
        outf=assert(io.open(infile..".ips."..n.."."..string.format("%02.2d",count),'w'))
        for k,v in pairs(ips6) do
            outf:write(k,"\n")
        end
        for k,v in pairs(ips4) do
            outf:write(k,"\n")
        end
        ips6={}
        ips4={}
        outf:close()
        count=count+1
        print("done with ".. linesreadtot .." lines, produced "..count*n.." uniq IPs in "..count.." files of "..n.." each.")
      end
    end
  else
    print("Line fail: " .. linesreadtot .. " - " .. line)
  end
end
