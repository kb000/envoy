LocalCongestionLimit filter
=====================

LocalCongestionLimit filter provides ability to describe, match, and act upon
HTTP requests with a user-described signature. The signature can be defined 
the same way as a RateLimit Action - with one or many Actions extracting
request metadata into a descriptor. Descriptors are then matched and
tallied for throttling actions.

Here is an example of LocalCongestionLimit filter configuration:

```
    - filterName: envoy.localcongestionlimiter
      filterConfig:
        filter_enabled: true
        congestion_limits:
        - name: RequestAnomaly
          descriptor_components:
            - header_value_match:
              # descriptor_key: path_match # TODO[UFES-8084]: Use after 1.24.
                descriptor_value: akamai-bot-sub-cat-request-anomaly
                headers:
                  - name: "AKAMAI-BOT"
                    contains_match: "Request Anomaly"
            - destination_cluster: {}
          descriptors:
            - key: header_value_match
            # key: path_match # TODO[UFES-8084]: Use after 1.24
              value: akamai-bot-sub-cat-request-anomaly
              descriptors:
                - key: destination_cluster
                  value: "viewitem-web-1-443" # Note: UFES GW cluster names aren't this clean. They look more like "ufesdwebgw/viewitem-web-1-443/80/6f53cb678e" or "agg_ufesdwebgw/viewitem-web-1-443/80/6f53cb678e"
                  limit: 
                    fixed: { limit: 35 }
                - key: destination_cluster
                  # value: No value specified - match any!
                  limit: 
                    fixed: { limit: 10 }
                  shadow_mode: true
          response_policy: interactive_bot_policy
        # TODO: Deliver response policies via Extension Config Discovery Service instead of including with each security policy.
        response_policies:
          name: interactive_bot_policy
          responses:
            - match:
                or_rules:
                  rules:
                    - header:
                        name: :authority
                        string_match:
                          suffix: ebay.de
                          ignore_case: true
                    - header:
                        name: accept-language
                        exact: de
                        ignore_case: true
              action: 
                static_response:
                  response_code: 200
                  source: { filename: "/srv/www-content/data/static/de.ebay.www._static_1.html" }
            - match:
                or_rules:
                  rules:
                    - header:
                        name: :authority
                        string_match:
                          suffix: ebay.fr
                          ignore_case: true
                    - header:
                        name: accept-language
                        exact: fr
                        ignore_case: true
              action: 
                static_response:
                  response_code: 200
                  source: { filename: "/srv/www-content/data/static/fr.ebay.www._static_1.html" }
            - match:
                header:
                  name: :path
                  prefix_match: /
                  case_sensitive: false
              action: 
                static_response:
                  response_code: 200
                  source: { filename: "/srv/www-content/data/static/com.ebay.www._static_1.html" }
            
          

```

The above localcongestionlimiter policy will extract a descriptor from an incoming request,
containing upstream cluster info and a flag whether the request is tagged as "Request Anomaly" by Akamai.
The extracted descriptor is then matched against the limit's descriptor tree. If all descriptor entries
are matched, the request is tallied against the matching limit. If a limit is exceeded, a response is 
chose from response_policies.
The filter uses first response policy to match, so here, it tries to match on headers and accept-language
for de and fr, and falls back to a match on path prefix: "/", which will always match.

Types of Congestion Limits
--------------------------

Fixed
----- 
This is static limiter. It tallies requests till the max specified concurrent requests has been reached, then marks them for action.


Types of Actions
----------------

**Static Response**: 
Return a static HTML page from the proxy itself so that upstream load is reduced.

**Redirect Action**: 
This is the same as the security filter. You can redirect the request to a different location.

**Drop Action**: 
Disconnect the request's connection.

**Monitor Action**: 
Add the info to access logs and metrics but do not act on the incoming request. This still sends the
request to upstream and the upstream load will not be reduced even when the localcongestionlimiter filter is
denying a request.
