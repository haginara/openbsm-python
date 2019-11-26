OpenBSM-Python
==============

Binding OpenBSM library for MacOS using Python


Install
=======
clone this project and use pip3

```pip3 install openbsm```

Features
========
* Read /var/audit/files like a `praudit`
    
    ```sudo python3 -m bsm.bin.praudit /dev/auditpipe```
    
    or after install

    ```sudo pyaudit /dev/auditpipe```

    ### Output example:
    ```
    header,173,11,ioctl(2),0,Thu Nov 21 18:05:36 2019, + 253 msec
    argument,2,0x40084106,cmd
    argument,3,0x7ffee20df4a0,arg
    path,/dev/auditpipe
    argument,1,0x4,fd
    attribute,8576,0,0,1202303120,320,184549377
    subject,jhchoi,root,wheel,root,wheel,81615(/Library/Frameworks/Python.framework/Versions/3.7/Resources/Python.app/Contents/MacOS/Python),100007,50331650,0.0.0.0
    return,success,0
    identity,0,,complete,,complete,0x
    trailer,173
    header,173,11,ioctl(2),0,Thu Nov 21 18:05:36 2019, + 253 msec
    argument,2,0x40044105,cmd
    argument,3,0x7ffee20df4a0,arg
    path,/dev/auditpipe
    argument,1,0x4,fd
    attribute,8576,0,0,1202303120,320,184549377
    subject,jhchoi,root,wheel,root,wheel,81615(/Library/Frameworks/Python.framework/Versions/3.7/Resources/Python.app/Contents/MacOS/Python),100007,50331650,0.0.0.0
    return,success,0
    ```

TODO
====
* Argtype classes
* Filter options for monitoring
