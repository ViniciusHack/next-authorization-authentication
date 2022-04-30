import { useContext } from "react";
import { AuthContext } from "../context/AuthContext";
import { validateUserPermissionsParams } from "../utils/validateUserPermissions";

 
 type UseCanParams = {
   permissions?: string[];
   roles?: string[];
 }
 
 export function useCan({permissions, roles}: UseCanParams) {
  const { user, isAuthenticated} = useContext(AuthContext);

  if(!isAuthenticated) {
    return false;
  }
  
  const userHasValidPermissions = validateUserPermissionsParams({
    user, 
    permissions,
    roles
  })

  return userHasValidPermissions;
 }