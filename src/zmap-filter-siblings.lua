#!/usr/bin/lua

-- takes zmap scan output files and calculates remaining sibling pairs

-- pattern to match zmap output csv: saddr,window,optionstext,tsdiff,wscale,success
local pattern = "([^,]+),([^,]+),([^,]+),+([^,]+),+([^,]+),+([^,]+)"
-- pattern to match old siblings: domain,ipv4,ipv6
local spattern = "([^,]+),([^,]+),([^,]+)"

local ips6 = {}
local ips4 = {}

local scan6 ={}
local scan4 ={}

local scanned6, scanned4, oldcands, newcands, meas, meas6, meas4, outmis, outopts = ...
if not scanned6 or not scanned4 or not oldcands or not newcands or not meas6 or not meas4 or not outmis or not outopts then
  print("usage: file.lua scanned6 scanned4 oldcands newcands meas meas6 meas4 outmissing outoptions")
  print("usage: scanned6 and scanned4 are zmap scan results")
  print("usage: oldcands is the old sibling candidate file, newcands is an output")
  print("usage: meas4 and meas6 are IPv4/IPv6 addresses of siblings, to be measured")
  print("usage: outmissing lists sibling canidates with 1 or more unresponsive hosts")
  print("usage: outoptions lists sibling candidates with different TCP options")
return
end
nc=assert(io.open(newcands,'w'))
f4=assert(io.open(meas4,'w'))
f6=assert(io.open(meas6,'w'))
f=assert(io.open(meas,'w'))
fmis=assert(io.open(outmis,'w'))
fopts=assert(io.open(outopts,'w'))

-- load v4 and v6 ips and fingerprints into table
for line in io.lines(scanned6) do
  local ip,window,optionstext,ignore1,wscale,ignore2= line:match(pattern)
  ips6[ip.."w"]=window --..optionstext..wscale
  ips6[ip.."t"]= optionstext
  ips6[ip.."s"]=wscale
  ips6[ip]=window..optionstext..wscale
end

i=0
for line in io.lines(scanned4) do
  local ip,window,optionstext,ignore1,wscale,ignore2= line:match(pattern)
  ips4[ip]=window..optionstext..wscale
  ips4[ip.."w"]=window --..optionstext..wscale
  ips4[ip.."t"]= optionstext
  ips4[ip.."s"]=wscale
  ips4[ip]=window..optionstext..wscale
end

-- write siblings with TS-enabled and similar option ipv4 and ipv6 addresses
-- to newcands, and ips to hitlist-style files
for line in io.lines(oldcands) do
  local domain,ip4,ip6 = line:match(spattern)
  if (domain ~= nil) then
    if(ips6[ip6] ~= nil and ips4[ip4] ~= nil) then
	    if( ips6[ip6] == ips4[ip4]) then
      		  nc:write(domain..",",ip4..",",ip6,"\n")
       		 scan6[ip6]=1
     		   scan4[ip4]=1
  	  else
		  err=""
		  if(ips4[ip4.."w"] ~= ips6[ip6.."w"]) then
			  err=err.."W"
		  end
		  if (ips4[ip4.."t"] ~= ips6[ip6.."t"]) then
			  err=err.."T"
		  end
		  if (ips4[ip4.."s"] ~= ips6[ip6.."s"]) then
			  err=err.."S"
		  end
		  if(err == "W") then
      		  	nc:write(domain..",",ip4..",",ip6,"\n")
       			scan6[ip6]=1
     			   scan4[ip4]=1
		   end
	   	 fopts:write(domain .. "," .. err, "," .. ip6 .. "," .. ips6[ip6].. "," .. ip4 .. ","  .. ips4[ip4].."\n")
	 end
    else
	 fmis:write(domain .. "," .. ip4 .. "," .. ip6 .. "\n")
    end
  end
end

for k,v in pairs(scan6) do
    f6:write(k,"\n")
    f:write(k,"\n")
end
for k,v in pairs(scan4) do
    f4:write(k,"\n")
    f:write(k,"\n")
end
f6:close()
f4:close()
f:close()
fopts:close()
fmis:close()
