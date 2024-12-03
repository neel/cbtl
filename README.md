Compiling
==========


Running
=======

# Initilization

Initilization process includes the following operations

- Creation of key pairs for the Managers
- Creation of access keys for the Managers
- Creation of key pairs for the Supervisors
- Creation of access keys for the Supervisors
- Creation of view keys for the Supervisors
- Creation of key pairs for the patients
- Initilization of a key value store with two databases (blocks, indexes)
- Create genesis blocks for all these users to the blocks database

```
./cbtl-init -M5 -S4 -P7
```

will create 5 managers, 4 supervisors and 7 patients.

```
./cbtl-init
```

without any parameters it will create 2 users of each type.


# Server

```
./cbtl-server -p master.pub -s master -v master.view
```

# To insert a Record

```
./cbtl-request -p manager-0.pub -s manager-0 -a manager-0.access -m master.pub -P patient-0.pub -I
```

After initial authentication it asks for plain text medical information.
Enter one Record and press enter.
Once all Records are inserted press enter again to finish.

# Fetch all Information

```
./cbtl-request -p manager-0.pub -s manager-0 -a manager-0.access -m master.pub -P patient-0.pub
```


# Request for Access

```
./cbtl-request -p manager-0.pub -s manager-0 -a manager-0.access -m master.pub
```

```
./cbtl-request -p super-0.pub -s super-0 -a super-0.access -m master.pub
```

# Read Blocks

```
./cbtl-read -u -p manager-0.pub -s manager-0 -m master.pub -l 5
```

```
./cbtl-read -v -p patient-0.pub -s patient-0 -m master.pub -l 5
```

```
./cbtl-read -x -s super-0 -a super-0.access -w super-0.view -t A53D040D85C9DBA35F7FD2A5B8C0A535AC2EF91452E63A05CA8F1331CC40F96E9B8EE3514F5C1777DB26D538A35A101C98BDA55EA43A4862ECB6353528A88004
```
