import swagger from "@elysiajs/swagger";
import { Elysia, status } from "elysia";
import { cookie } from '@elysiajs/cookie'
import jwt from 'jsonwebtoken'
import 'dotenv/config'

const secret = process.env.JWT_SECRET
if (!secret) throw new Error('JWT_SECRET not defined')

const PORT = 3000
const users = [
  { id: 1, username: "admin", password: "admin123", role: "admin" },
  { id: 2, username: "user", password: "user123", role: "basic" }
];

const auth = new Elysia()
  .derive({ as: 'scoped' }, (request) => {
    if (!request.cookie?.token?.value) {
      return { user: null, isAuthenticated: false }
    }

    try {
      const decoded = jwt.verify(request.cookie.token.value, secret) as { userId: number; userName: string; role: string };
      const user = users.find(u => u.id === decoded.userId && u.username === decoded.userName);
      if (!user) {
        return { user: null, isAuthenticated: false }
      }
      return { user: user, isAuthenticated: true }
    } catch (error) {
      return { user: null, isAuthenticated: false }
    }
  })
  .onBeforeHandle((request) => {
    if (!request.isAuthenticated) {
      return status(401)
    }
  })

const authenticatedRoutes = new Elysia()
  .use(auth)
  .get('/api/public', (request) => {
    return {
      message: "PUBLIC ACCESS GRANTED",
      user: request.user,
    }
  })
  .get('/api/chat', (request) => {
    return {
      message: "PUBLIC CHATS ACCESSED"
    }
  })

const adminRoutes = new Elysia()
  .use(auth)
  .onBeforeHandle((request) => {
    if (!request.user || request.user.role !== 'admin') {
      return status(403)
    }
  })
  .get('/api/protected', (request) => {
    return {
      message: "PROTECTED ACCESS GRANTED",
      user: request.user
    }
  })
  .get('/api/chat/history', (request) => {
    return {
      message: "PROTECTED chat history",
      user: request.user
    }
  })
  .delete('/api/chat/history', (request) => {
    return {
      message: "PROTECTED delete chat history",
      user: request.user
    }
  })

type LoginData = {
  username: string
  password: string
}

const app = new Elysia()
  .use(cookie())
  .use(swagger())
  .get('/', () => {
    return { message: "hello world" }
  })
  .post('/login', ({ body, cookie }: { body: LoginData, cookie: any }) => {
    if (!body?.username || !body?.password) {
      return { error: "Missing Username or Password" }
    }

    const user = users.find((u) => u.username === body.username && u.password === body.password)
    if (!user) {
      return { error: "Incorrect Username or Password" }
    }

    const token = jwt.sign(
      {
        userId: user.id,
        userName: user.username,
        role: user.role
      },
      secret,
      {
        algorithm: 'HS256',
        expiresIn: '1h'
      }
    );

    cookie.token.set({
      value: token,
      httpOnly: true,
      path: '/',
      maxAge: 60 * 60,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    })

    return {
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    }
  })
  .post('/logout', ({ cookie }) => {
    cookie.token.remove()
    return { success: true, message: "Logged out successfully" }
  })
  .use(authenticatedRoutes)
  .use(adminRoutes)
  .listen(PORT)

console.log(
  `🦊 Elysia is running at http://${app.server?.hostname}:${app.server?.port}`
);