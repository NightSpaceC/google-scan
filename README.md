# google-scan

This tool can be used to get all the reachable hosts in the entire Google IP range.

It can work in only Linux and Windows now.

It support only IPv4 now.

You should download [goog.json](https://www.gstatic.com/ipranges/goog.json) and put it in the work directory first.

Then

```
./google-scan -n <maximum number of threads>
```

With more threads, it will be more quickly, but more reachable hosts will be ignored.

It is recommended to set it from 4 to 8, and the process will be finished in several hours.