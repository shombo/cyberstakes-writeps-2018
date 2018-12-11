# Munitions Inventory System - Points: ???

### Description:

<missing since site is down>

### Hints

<missing since site is down>

### Solution

*Note: I'll add screenshots once the site is back up*

The hint references checking out `"`. Adding this to a query, you can an error that references AQL. I never heard of this type of query language and found this specific [IBM Query Language](https://www.ibm.com/support/knowledgecenter/en/SSPT3X_4.2.5/com.ibm.swg.im.infosphere.biginsights.aqlref.doc/doc/aql-overview.html). Looking into the syntax and the error, I decide to try a basic OR
`search=i%25%22+OR+DATA.name+LIKE+%22`. This dumps the entire DB - find the flag.

### Flag: ``
