echo "SELECT encode(y, 'hex') as y, encode(random, 'hex') as random, name, age FROM public.persons;" | psql -U crn_user -d crn -x
