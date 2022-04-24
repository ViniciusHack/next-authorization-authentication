import axios, { AxiosError } from 'axios';
import { parseCookies, setCookie } from 'nookies';
import { signOut } from '../context/AuthContext';
import { AuthTokenError } from '../errors/AuthTokenError';

let isRefreshing = false;
let failedRequestsQueue = [];

export function setupAPIClient(ctx = undefined) {
  let cookies = parseCookies(ctx);

  const api = axios.create({
    baseURL: "http://localhost:3333",
    headers: {
      Authorization: `Bearer ${cookies['next-authorization-authentication.token']}`
    }
  });
  
  api.interceptors.response.use(response => {
    return response
  }, (error: AxiosError) => {
    if(error.response.status === 401) {
      if(error.response.data?.code === 'token.expired') {
        cookies = parseCookies(ctx);
  
        const { 'next-authorization-authentication.refreshToken': refreshToken } = cookies;
  
        const originalConfig = error.config;
  
        if(!isRefreshing) {
          isRefreshing = true;
          
          api.post('/refresh', {
            refreshToken,
          }).then( response => {
            const { token } = response.data;
    
            setCookie(ctx, 'next-authorization-authentication.token', token, {
              maxAge: 60 * 60 * 24 * 30, // 30 days
              path: '/'
            })
            setCookie(ctx, 'next-authorization-authentication.refreshToken', response.data.refreshToken, {
              maxAge: 60 * 60 * 24 * 30, // 30 days
              path: '/'
            })
            
            api.defaults.headers["Authorization"] = `Bearer ${token}`;
  
            failedRequestsQueue.forEach(request => request.onSuccess(token));
            failedRequestsQueue = [];
          }).catch(err => {
            failedRequestsQueue.forEach(request => request.onFailure(err));
            failedRequestsQueue = [];
  
            if(process.browser){ // typeof window !== undefined
              console.log("Client")
              return signOut();
            } else {
              console.log("Server")
              return Promise.reject(new AuthTokenError())
            }

          }).finally(() => {
            isRefreshing = false;
          });
        };
  
        return new Promise((resolve, reject) => {
          failedRequestsQueue.push({
            onSuccess: (token: string) => {
              originalConfig.headers['Authorization'] = `Bearer ${token}`;
  
              resolve(api(originalConfig));
            },
            onFailure: (err: AxiosError) => {
              reject(err);
            },
          });
        });
      } else {
        signOut();
      }
    }
  
    return Promise.reject(error);
  })

  return api
}