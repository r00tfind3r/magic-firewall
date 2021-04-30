# magic-firewall-manager
Simple-to-use graphical user interface to add, delete, or modify firewall rules in Linux

This is a collaborative project that @ejdivi and I worked on for our final project in a Cyber Security course.
Neither of us have written a GUI prior to this and thought it would be a fun learning experience.

The magic-firewall-manager utilizes the PySimpleGUI module and Python to provide a convenient way to modify iptables in Linux.
It creates command-line iptables commands and executes them through subprocess calls based on user-inputs in the GUI.

This tool is in no way intended to be used on production machines or servers.  
Rather, a fun and easy way to setup custom firewall rules without having to type them in manually.

The tool obviously requires sudo access to modify any firewall rules and can simply be executed on the command-line.

Feel free to suggest edits, provide feedback, or use the tool for personal use.
