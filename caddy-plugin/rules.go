package caddy_plugin

// Rule interface represents an evaluation rule
type Rule interface {
	// Evaluate takes the set of current valid sessions.
	// It returns true if the rule is satisfied, and a list of servers that
	// still need to be authenticated against if the rule is not satisfied.
	Evaluate(sessions map[string]*Session) (bool, []string)
}

// AllowRule checks if the user has at least one of the required roles on a specific server
type AllowRule struct {
	Server string
	Roles  []string
}

func (r *AllowRule) Evaluate(sessions map[string]*Session) (bool, []string) {
	sess, ok := sessions[r.Server]
	if !ok || sess == nil {
		// Need to authenticate with this server
		return false, []string{r.Server}
	}

	if len(r.Roles) == 0 {
		return true, nil // No specific roles required, just authentication
	}

	userRoleRaw, ok := sess.Claims["role"]
	if !ok {
		return false, nil // Authenticated, but missing role claim
	}

	// Support both string and []interface{} for roles
	if userRole, ok := userRoleRaw.(string); ok {
		for _, allowedRole := range r.Roles {
			if allowedRole == userRole {
				return true, nil
			}
		}
	} else if userRoles, ok := userRoleRaw.([]interface{}); ok {
		for _, allowedRole := range r.Roles {
			for _, ur := range userRoles {
				if urStr, ok := ur.(string); ok && urStr == allowedRole {
					return true, nil
				}
			}
		}
	}

	return false, nil // Authenticated, but does not have the required role
}

// RequireAllRule checks if all nested rules evaluate to true
type RequireAllRule struct {
	Rules []Rule
}

func (r *RequireAllRule) Evaluate(sessions map[string]*Session) (bool, []string) {
	var missingServers []string
	satisfied := true

	for _, rule := range r.Rules {
		ruleSatisfied, missing := rule.Evaluate(sessions)
		if !ruleSatisfied {
			satisfied = false
			missingServers = append(missingServers, missing...)
		}
	}

	return satisfied, deduplicate(missingServers)
}

func deduplicate(servers []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, s := range servers {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}
