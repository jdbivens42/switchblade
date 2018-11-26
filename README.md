Switchblade.py
======
**Switchblade** is a script based on the python Netcat library (nclib) that catches raw tcp shells in the same way as a netcat listener, but adds several convenience features such as a command history and local command execution.

```
$ ./switchblade [-p Port] [--send-log filepath] [--recv-log filepath]
 Victim Connected!
$ <This prompt now sends commands to the victim>
```
## Version 
* Version 0.1

## Requirements  
Switchblade is designed to run in python 3.7 and is not compatible with python 2.  
The following packages must be installed for switchblade to work properly:  

* nclib
* prompt_toolkit

These can be installed with the command `pip3 install nclib prompt_toolkit`

## The Switchblade Class
Switchblade may be imported as a class in other python projects.  
To use switchblade as it runs on the command line, instantiate a switchblade object

```
import switchblade
sb = switchblade(port, send_log, recv_log)
```
then call the listener function

```
sb.listener()
```
The initialization blocks until a connection is received, and listener is a blocking call that runs on an indefinite loop, so be careful when calling them.  
The switchblade class includes several functions which may be called independently from other python scripts.
these include

`sb.send()` - a wrapper for the netcat send function

`sb.recv()` - a looping function for receiving input from the victim. Meant to run in a background thread

`sb.runCommand()` - executes a command on the client machine and returns the result as a string

`sb.builtins()` - currently a placeholder. Provides support for executing client-side python functions on command.

## Contact
#### Connor Gannon (Gin&Miskatonic)
* Homepage: [users.csc.tntech.edu/~cmgannon42](http://users.csc.tntech.edu/~cmgannon42)
* e-mail: [connor.gannon@outlook.com](mailto:connor.gannon@outlook.com)
* Discord: Gin&Miskatonic#5933
