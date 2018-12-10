const express = require('express')
const ejs = require('ejs').__express
const app = express()
const { db } = require('./db')
const { logger } = require('./logger')

// logs access to page based on url
const logaccess = (req) => {
  let tags
  const log = {
    url: req.url,
    clientIP: req.headers['x-forward-for'],
    userAgent: req.headers['user-agent']
  }
  switch (req.url) {
    case '/shipping':
      tags = ['shipping', 'operations']
      logger.sendlog(log, tags, db)
      break
    case '/quality':
      tags = ['quality', 'engineering']
      logger.sendlog(log, tags, db)
      break
    case '/billing':
      tags = ['billing', 'accounting', 'sales']
      logger.sendlog(log, tags, db)
      break
    case '/orders':
      tags = ['orders', 'sales']
      logger.sendlog(log, tags, db)
      break
    case '/sales':
      tags = ['sales']
      logger.sendlog(log, tags, db)
      break
    case '/inventory/cpus':
      tags = ['inventory', 'cpu']
      logger.sendlog(log, tags, db)
      break
    case '/inventory/boards':
      tags = ['inventory', 'board']
      logger.sendlog(log, tags, db)
      break
  }
}

// create express application and set templating engine
app.use(express.static('public'))
app.set('view engine', 'ejs')
app.engine('.ejs', ejs)

// displays home page
app.get('/', (req, res) => {
  logaccess(req)
  res.render('index')
})

// displays devices that have shipped
app.get('/shipping', (req, res) => {
  logaccess(req)
  res.render('shipping', {db: db.filter(i => (i.status === 'Shipped' || i.status === 'Delivered'))})
})

// displays quality control checks
app.get('/quality', (req, res) => {
  logaccess(req)
  res.render('quality', {db})
})

// displays device board firmware version
app.get('/assembly', (req, res) => {
  logaccess(req)
  res.render('assembly', {db})
})

// displays billing information
app.get('/billing', (req, res) => {
  logaccess(req)
  res.render('billing', {db})
})

// displays order information
app.get('/orders', (req, res) => {
  logaccess(req)
  res.render('orders', {db})
})

// displays order information
app.get('/sales', (req, res) => {
  logaccess(req)
  res.render('sales', {db})
})

// displays cpu inventory
app.get('/inventory/cpu', (req, res) => {
  logaccess(req)
  res.render('inventory_cpu', {db})
})

// displays board inventory
app.get('/inventory/boards', (req, res) => {
  logaccess(req)
  res.render('inventory_board', {db})
})

// displays board inventory
app.get('/logs', (req, res) => {
  logaccess(req)
  res.render('logs', {logs: logger.logs})
})

// run server
const server = app.listen(8080, () => {
  console.log(`Server running → PORT ${server.address().port}`);
});
