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
crn-init -M5 -S4 -P7
```

will create 5 managers, 4 supervisors and 7 patients.

```
crn-init
```

without any parameters it will create 2 users of each type.


# Server

```
crn-server -p master.pub -s master -v master.view
```


# Request for Access

```
./crn-request -p manager-0.pub -s manager-0 -a manager-0.access -m master.pub
```

```
./crn-request -p super-0.pub -s super-0 -a super-0.access -m master.pub
```

# Read Blocks

```
crn-read -u -p manager-0.pub -s manager-0 -m master.pub -i 5
```

```
crn-read -v -p patient-0.pub -s patient-0 -m master.pub -i 5
```

```
crn-read -x -s super-0 -a super-0.access -w super-0.view -t A53D040D85C9DBA35F7FD2A5B8C0A535AC2EF91452E63A05CA8F1331CC40F96E9B8EE3514F5C1777DB26D538A35A101C98BDA55EA43A4862ECB6353528A88004
```
