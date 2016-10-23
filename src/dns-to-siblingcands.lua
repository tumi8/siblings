#!/usr/bin/lua

-- convert raw v4 and v6 DNS answers into sibling candidates and IP hit lists
-- logic: domains with both A and AAAA generate sibling candidates
-- input files are assumed to stem from massDNS and have the format of
-- domain.tld.	1800	IN	A	1.2.3.4
-- domain.tld.	1800	IN	AAAA	1:2::3

-- match n whitespace-char (%s) separated columns
local pattern = "([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+([^%s]+)"

local v6doms = {}
local bothdoms = {}

local file1, file2, siblingcands = ...
if not file1 or not file2 or not siblingcands then
	print("usage: file.lua v6-dns.txt v4-dns.txt sibling-cands")
	return
end
sc=assert(io.open(siblingcands,'w'))
for line in io.lines(file1) do
	local domain, ttl, bla, rr, ip = line:match(pattern)
	if rr == "AAAA" then
		if not v6doms[domain] then
			-- if domain not existent, create table
			v6doms[domain] = {}
		end
		-- add specific IP to domain table
		v6doms[domain][ip]=1
	end
end

for line in io.lines(file2) do
	local domain, ttl, bla, rr, ip = line:match(pattern)
	if rr == "A" then
		if v6doms[domain] then
			-- if domain exists in v4, create sibling entry
			if not bothdoms[domain] then
				-- if not existant in bothdoms, create
				bothdoms[domain]={}
				bothdoms[domain]["v6"] = {}
				bothdoms[domain]["v4"] = {}
				-- create entries for all IPv6 addresses for domain
				for k,v in pairs(v6doms[domain]) do
					bothdoms[domain]["v6"][k] = 1
				end
			end
			-- add IPv4 address to domain
			bothdoms[domain]["v4"][ip]=1
		end
	end
end

-- generate domain,ipv4,ipv6 triples (multiple lines in case of several IPs)
for k,v in pairs(bothdoms) do
	for k4,v4 in pairs(v["v4"]) do
		for k6,v6 in pairs(v["v6"]) do
			sc:write(k..","..k4..","..k6,"\n")
		end
	end
end

sc:close()
