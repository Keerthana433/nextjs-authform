import NextAuth, { Awaitable, RequestInternal } from "next-auth";
import User from "@/models/user";
import connectToDatabase from "@/lib/mongodb";
import bcrypt from 'bcryptjs';
import CredentialsProvider from "next-auth/providers/credentials";
import Github from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";

const handler = NextAuth({
    session: {
        strategy: 'jwt',
    },
    providers: [
        GoogleProvider({
            clientId: process.env.GOOGLE_ID as string,
            clientSecret: process.env.GOOGLE_SECRET as string,
          }),
        Github({
            clientId: process.env.GITHUB_ID as string,
            clientSecret: process.env.GITHUB_SECRET as string
        }),
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: {},
                password: {}
            },
            async authorize(credentials) {
               try{
                await connectToDatabase();
                const user = await User.findOne({ email: credentials?.email })
                if(!user){
                    throw new Error("")
                }
                const isValidPassword = await bcrypt.compare(
                    credentials?.password ?? "", user.password as string
                )
                if(!isValidPassword) {
                    throw new Error("")
                }
                return user;
               } catch {
                return null
               } 
            }
        })
    ],
    callbacks: {
        async jwt({token, user}) {
            if(user){
                token.id = user.id;
                token.email = user.email;
            }
            return token
        },
        async session({ session, token }) {
            if(token){
                session.user = {
                    email: token.email,
                    name: token.name,
                    image: token.picture
                }
            }
            return session
        }
    },
    pages: {
        signIn: "/sign-in"
    },
    secret: process.env.NEXTAUTH_SECRET
    })

    export { handler as GET, handler as POST };