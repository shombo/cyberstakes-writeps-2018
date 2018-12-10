# Stealth Access - Points: ???

### Description:

<missing since site is down>

### Hints

<missing since site is down>

### Solution

Based on the description and the hints, the goal of this challenge is to gain some information about device `36D1C3D365409932BF0B42335E661C2C` without making it in the application's log. Haphazardly browsing the page, you notice this ID appearing on just about every page with some key piece of information missing. Looking at the well-documented source, you notice a `logaccess` function with a switch that is responsible for updating the log with your user-agent so your goal is to avoid any link that calls this function. Those links can be found inside the switch:
```  switch (req.url) {
    case '/shipping':
    case '/quality':
    case '/billing':
    case '/orders':
    case '/sales':
    case '/inventory/cpus':
    case '/inventory/boards':
```

For the pages that are browsable, you need to look at the various `app.get` functions:

```
app.get('/', (req, res) => {
app.get('/shipping', (req, res) => {
app.get('/quality', (req, res) => {
app.get('/assembly', (req, res) => {
app.get('/billing', (req, res) => {
app.get('/orders', (req, res) => {
app.get('/sales', (req, res) => {
app.get('/inventory/cpu', (req, res) => {
app.get('/inventory/boards', (req, res) => {
app.get('/logs', (req, res) => {
```

Comparing these two, you will notice two links you can visit without being logged, `'/assembly'` as well as the non-pluralized `/inventory/cpu`. Visit these two pages, grab the extra provide information in the associated ID fields, and you have your flag.

### Flag: `96f81ae1f21ddc6da946adcb0f05f6d3`
