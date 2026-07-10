[Español](decisions.es.md)

# Technical Decisions

## OSV API

I decided to use this API because it supports a wide variety of package ecosystems, including 
several of those used by GitHub Advisory Database, which simplifies the integration of both 
sources of information.
OSV API uses GHSA identifiers among other vulnerability identifiers, allowing the results obtained
to be correlated with GitHub Advisory Database. This matched the project requirements for performing
package and version searches, as well as dependency file scanning.

## SQLite

The cache implemented with SQLite prevents multiple API calls when the user executes repeated queries. 
This improves response times and reduces unnecessary requests to external APIs.
Although the individual time improvement may seem small, this type of optimization is important in
command-line tools where response speed directly affects the user experience.

## ThreadPoolExecutor

In addition to cache storage, I implemented multiple independent queries using `ThreadPoolExecutor` 
to reduce execution time during the scanning process.
This process represents the most expensive operation in the application due to the number of packages
that may exist in a dependency file. Therefore, concurrent execution improves performance and leaves 
room for future optimizations.

