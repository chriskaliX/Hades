# HIDS-Linux

> Linux HIDS based on Netlink Connector, cn_proc. Learn from [kinvolk](https://github.com/kinvolk/nswatch/blob/5ed779a0cbdfa80403ea42909ca157a89719f159/nswatch.go)

You can not catch all the cmdline cause sometimes pid file has disappeared, expecially when you do `id`, `whoami` which run in a very short time. Cmdline like `sleep` barely failed. Here is a pic for demo.


![image](https://github.com/chriskaliX/HIDS-Linux/blob/main/hids1.png)
