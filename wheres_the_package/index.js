const express = require("express")
const prettier = require("prettier")
const figlet = require("figlet")
const math = require("mathjs")
const randomstring = require("randomstring")
const faker = require("faker")
const bodyParser = require("body-parser")
const md5 = require("md5")
const path = require("path")
const fs = require("fs")
const http = require("http")
const net = require("net")

const app = express()
const port = process.argv[2]

const whitelist = ["yourself", "index.js", "package.json"]

app.use(bodyParser.urlencoded({ extended: true }))

app.use(express.static("public"))

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname + "/index.html"))
})

app.post("/chat", (req, res) => {
  let { text } = req.body

  if (text.startsWith("tell me about ")) {
    let file = text.slice(14)
    if (whitelist.indexOf(file) == -1)
      return res.json({
        text: "I don't think I can really talk about that, sorry"
      })

    if (file === "yourself") {
      file = "index.js"
    }

    let file_text = fs.readFileSync(path.join(__dirname, file)).toString()
    try {
      file_text = prettier.format(file_text, { semi: false, parser: "babylon" })
    } catch (e) {}

    return res.json({
      text: "Maybe this will help explain it better:",
      file: file_text
    })
  }

  if (text.startsWith("hash ")) {
    return res.json({ text: `The hash is ${md5(text.slice(5))}` })
  }

  if (text.startsWith("draw ")) {
    figlet(text.slice(5), (err, data) => {
      if (err)
        return res.json({ text: "Ouch I couldn't draw that, its too hard" })
      return res.json({ text: "Here is my best try", file: data })
    })
    return
  }

  if (text.match(/(your\s+email)/i)) {
    return res.json({ text: `My email is ${faker.internet.email()}` })
  }
  if (text.match(/(your\s+name)/i)) {
    return res.json({ text: `My name is ${faker.name.findName()}` })
  }
  if (text.match(/(random)/i)) {
    return res.json({ text: randomstring.generate() })
  }

  if (text.startsWith("what is ")) {
    try {
      let val = math.eval(text.slice(8))
      return res.json({ text: val })
    } catch (e) {
      return res.json({
        text: "I'm sorry I had a hard time trying to answer you",
        err: `Error ${e}`
      })
    }
  }

  if (text.match(/^(hi|hello|hey)/i)) {
    return res.json({ text: "Hi! How are you?" })
  }
  if (text.match(/^(how are you|hbu|you?)/i)) {
    return res.json({ text: "I'm doing alright" })
  }
  if (text.match(/^(good|great|happy)/i)) {
    return res.json({ text: "Thats great!" })
  }
  if (text.match(/(help)/i)) {
    return res.json({
      text:
        'I\'m your new best friend. If you want to know more about me just ask "tell me about yourself"'
    })
  }

  let responses = [
    "Hey there",
    "I'm here to help",
    "If you are confused how to interact with me, just ask for some help",
    "Let me draw you some art! Just ask",
    "I'm pretty good with math you know"
  ]

  res.json({ text: responses[Math.floor(Math.random() * responses.length)] })
})

const sock = `/tmp/socat.${port}`

if (fs.existsSync(sock)) {
  fs.unlinkSync(sock)
}

app.listen(sock, function() {
  fs.chmodSync(sock, 0770)
})
