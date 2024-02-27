package example

import future.keywords.in

analyze[risk_path] {
	some index, perm in input.sub_resource_permissions
	perm.encrypted == false
    some i, pol in perm.acl
    pol ==  "RiskyWrite"
    risk_path := sprintf("sub_resource_permissions.%v.encrypted", [index])
}







