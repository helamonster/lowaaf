do_dumpall()
{


curl -s \
	  'http://localhost:8889/api.php?action=paraminfo&format=json' 

}


do_dumpall

exit 0

curl -s \
	  'http://localhost:8889/api.php?action=paraminfo&modules=edit&format=json' \
		| jq
#		| jq '.paraminfo.modules[0].parameters[]
#      | {name, type}'

exit $?

curl -s \
	  'http://localhost:8889/api.php?action=paraminfo&modules=edit&format=json' #\
#		| jq '.paraminfo.modules[0].parameters[].name'

exit $?


curl -s \
	  'http://localhost:8889/api.php?action=paraminfo&format=json' #\
		#| jq '.paraminfo.modules[].name'

exit $?

curl -s \
	  'http://localhost:8889/api.php?action=paraminfo&format=json' \
		| jq

