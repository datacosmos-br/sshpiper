// Package libplugin: User and Group Utility Helpers for SSHPiper Plugins
//
// Provides helpers for querying user group membership and checking group authorization in a reusable, idiomatic way.
//
// # Features
//   - UserGroupNames: Returns the group names for a given user.User
//   - UserGroupHas: Returns true if the user is a member of the given group
//
// # Usage Example
//
//	groups, err := libplugin.UserGroupNames(usr)
//	ok := libplugin.UserGroupHas(groups, "admin")
package libplugin

import (
	"os/user"
)

// UserGroupNames returns the group names for a given user.User.
//
// Example:
//
//	groups, err := libplugin.UserGroupNames(usr)
func UserGroupNames(usr *user.User) ([]string, error) {
	groupIds, err := usr.GroupIds()
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, groupId := range groupIds {
		grp, err := user.LookupGroupId(groupId)
		if err != nil {
			return nil, err
		}
		groups = append(groups, grp.Name)
	}
	return groups, nil
}

// UserGroupHas returns true if the user is a member of the given group.
//
// Example:
//
//	ok := libplugin.UserGroupHas(groups, "admin")
func UserGroupHas(userGroups []string, group string) bool {
	for _, g := range userGroups {
		if g == group {
			return true
		}
	}
	return false
}
