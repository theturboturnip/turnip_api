# turnip_api

This server handles all endpoints hosted at `https://api.theturboturnip.com/`.

# Endpoints

## turnip_api_search

This API intends to provide basic web search functionality that uses search bar autocomplete to push the user in useful, known-good directions.
For example, searching a movie title provides autocomplete suggestions that link directly to the Wikipedia or TMDB page, instead of leading the user to a search results page with a minefield of potential slop.
Unit conversion is built in with strict-yet-permissive syntax "X Y in Z", and reliably triggers on known units, currencies, and timezones.

- `GET /search?q=<QUERY>`
  - Redirects from the query to a page that can handle it using the HTTP code [302 Found](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/302)
  - By default, redirects to <https://kagi.com> search.
  - "special suggestions" (see below) are redirected to specific websites.
- `GET /search/suggest?n=<int DEFAULT 3>&q=<QUERY>`
  - Generates search suggestions to be displayed inside the search bar.
    - Returns suggestions by the Firefox schema: a JSON array `["Original Query", ["Suggestion 1", "Suggestion 2"...]]`
    - Suggestions are layered, and "special suggestions" are prefixed with "~\<ZWJ\>" and a tag that indicates where they should be redirected.
      - For example, a calculation "1pm EST in BST" may suggest "~time 1pm EDT in BST = 6pm BST", which when clicked and passed through the search endpoint will redirect to a WolframAlpha page for "1pm EDT in BST".
      - Note that EDT (Eastern Daylight Time) is returned instead of EST (Eastern Standard Time) - this is intended. Timezone conversions look up what abbreviated zones are _actually_ in use, based on a user-provided date e.g. "2026-04-04 1pm" or using the current date, and only returns those. If, on that day, all of America is in daylight-savings, EDT will be the only valid option.
    - First, a calculation layer parses the query as "X Y in Z" i.e. X value in Y unit converted to Z unit, and attempts to complete the conversion.
      - Length, temperature, and time conversions are computed locally.
      - Timezone conversions are computed locally.
      - Currency conversions are computed locally backed by data updated bi-hourly from <https://openexchangerates.org> (when the server has an API token).
    - If a calculation is detected, one or more answers are provided. If no answers can be calculated (e.g. the server doesn't understand what units are used), a single suggestion will be provided to link to WolframAlpha.
      - Calculation suggestions are prefixed with "~calc" or "~time" as appropriate.
    - If the query was not a calculation, it will be searched on Wikipedia (always) and TMDB (when the server has an API token).
      - Up to `n` results from each site will be returned, each prefixed with "~wiki" or "~tmdb" as appropriate.
      - TODO this is NOT provided when the query is a calculation, which may cause problems when trying to search for specific things formatted "X Y in Z"...
    - Generic suggestions pulled from a basic search suggestion API are returned at the end.
      - These are backed by the Kagi suggestion API at <https://kagisuggest.com/api/autosuggest?q=QUERY>, but the server can be configured at boot-time to use another Firefox-style API like <https://suggestqueries.google.com/complete/search?client=firefox&q=QUERY>.
      - DuckDuckGo <https://duckduckgo.com/ac/?q=QUERY&kl=EN> uses a different style and is not yet supported.
    - All APIs pinged are rate limited, so I think this server will be a good client, but I'm not sure how it will behave under heavy load. Thankfully, it will not be under heavy load?

# Panic Safets

`.expect()` is used when certain functions either

- can always be assumed to never fail at runtime
- are only called at startup time and in effect are start-of-day assertions

`.unwrap()` is used on the RwLock for currency data inside `turnip_api_search`.
RwLocks only fail when poisoned (panic-while-locked), and RwLock usage has been audited to ensure poisoning cannot happen. Any state that would induce panic or failure is handled before taking the lock, not after.

TODO some fuzzing would be nice.
