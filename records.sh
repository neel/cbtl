echo "SELECT anchor, encode(hint, 'hex') as hint, encode(random, 'hex') as random, created, \"case\" FROM records;" | psql -U cbtl_user -d cbtl -x
