Skip to content
Product 
Team
Enterprise
Explore 
Marketplace
Pricing 
Search
Sign in
Sign up
weltliter
/
idshwk4
Public
Code
Issues
Pull requests
Actions
Projects
Wiki
Security
Insights
idshwk4/test.zeek
@weltliter
weltliter Update test.zeek
Latest commit cd3a1bb 3 days ago
 History
 1 contributor
30 lines (25 sloc)  1.22 KB
  
@load base/frameworks/sumstats

event http_reply(c:connection, version:string, code:count, reason:string){
	SumStats::observe("all_response", SumStats::Key($host = c$id$orig_h), SumStats::Observation($num = 1));
	if(code == 404){
		SumStats::observe("404_response", SumStats::Key($host = c$id$orig_h), SumStats::Observation($num = 1));
		SumStats::observe("404_url", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str = c$http$uri));
	}
}


event zeek_init(){
	local r1 = SumStats::Reducer($stream = "all_response",$apply = set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream = "404_response",$apply = set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream = "404_url",$apply = set(SumStats::UNIQUE));
	
	SumStats::create([$name = "404 statistics",
		$epoch = 10mins,
		$reducers = set(r1, r2, r3),
		$epoch_result(ts:time, key: SumStats::Key, result: SumStats::Result) = {
			local rall = result["all_response"];
			local r404r = result["404_response"];
			local r404url = result["404_url"];

			if(r404r$sum > 2 && r404r$sum/rall$sum > 0.2 && r404url$unique/r404r$sum > 0.5){
				print fmt("%s is a scanner with %s scan attemps on %s urls", key$host, r404r$sum, r404url$sum);
			}
		}
	]);
}
© 2022 GitHub, Inc.
Terms
Privacy
Security
Status
Docs
Contact GitHub
Pricing
API
Training
Blog
About
Loading complete
