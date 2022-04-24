import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from "next";
import { destroyCookie, parseCookies } from "nookies";
import { AuthTokenError } from "../errors/AuthTokenError";


export function withSSRAuth<P>(fn: GetServerSideProps<P>):GetServerSideProps {
  return async (ctx: GetServerSidePropsContext): Promise<GetServerSidePropsResult<P>> => {
    const cookies = parseCookies(ctx);

    if(!cookies['next-authorization-authentication.token']) {
      return {
        redirect: {
          destination: '/',
          permanent: false
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