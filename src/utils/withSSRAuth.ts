import jwtDecode from "jwt-decode";
import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from "next";
import { destroyCookie, parseCookies } from "nookies";
import { AuthTokenError } from "../errors/AuthTokenError";
import { validateUserPermissionsParams } from "./validateUserPermissions";

type WithSSRAuthOptions = {
  permissions?: string[];
  roles?: string[];
}

export function withSSRAuth<P>(fn: GetServerSideProps<P>, options?: WithSSRAuthOptions):GetServerSideProps {
  return async (ctx: GetServerSidePropsContext): Promise<GetServerSidePropsResult<P>> => {
    const cookies = parseCookies(ctx);
    const token = cookies['next-authorization-authentication.token'];

    if(!token) {
      return {
        redirect: {
          destination: '/',
          permanent: false
        }
      }
    }

    if(options) {
      const user = jwtDecode<{ permissions: string[], roles: string[]}>(token);
      const { roles, permissions } = options;

      const userHasValidPermissions = validateUserPermissionsParams({
        user, 
        permissions,
        roles
      })

      if(!userHasValidPermissions) {
        return {
          redirect: {
            destination: "/dashboard",
            permanent: false
          }
        }
      }
    }

    try {
      return await fn(ctx);
    } catch (err) {
      console.log("****ERROR****:");
      console.log(err);
      if(err instanceof AuthTokenError) {
        console.log("It's an auth token error") // Não caindo aqui.
        destroyCookie(ctx, 'next-authorization-authentication.token');
        destroyCookie(ctx, 'next-authorization-authentication.refreshToken');

        return {
          redirect: {
            destination: "/",
            permanent: false
          }
        }
      } else {
        console.log("It's NOT an auth token error")
      }
    }
  }
}