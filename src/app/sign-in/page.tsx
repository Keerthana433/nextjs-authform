"use client"

import React, { useState } from 'react';

//shadcn ui
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardDescription, CardContent, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";

//react icons
import { FaGithub } from "react-icons/fa";
import { FcGoogle } from "react-icons/fc";
import { useRouter } from 'next/navigation';
import { signIn } from 'next-auth/react';
import { toast } from 'sonner';
import { TriangleAlert } from 'lucide-react';


const SignUp = () => {
	const [email, setEmail] = useState<string>("");
	const [password, setPassword] = useState<string>("")
	const [pending, setPending] = useState(false);
	const [error, setError] = useState("");
	const router = useRouter();
	
	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setPending(true);
		const res = await signIn("credentials", {
			redirect: false,
			email,
			password
		})
		if(res?.ok){
			router.push("/");
			toast.success("Login Successful")
		} else if(res?.status === 401){
			setError("Invaild Credentials");
			setPending(false)
		} else {
			setError("Something Went Wrong");
		}
	}
	
	const handleProvider = (
		event: React.MouseEvent<HTMLButtonElement>,
		value: "github" | "google"
	) => {
		event.preventDefault();
		signIn(value, { callbackUrl: "/" })
	};

	return (
		<div className="h-full flex items-center justify-center bg-[#1b0918]">
			<Card className="md:h-auto w-[80%] sm:w-[420px] p-4 sm:p-8">
				<CardHeader>
					<CardTitle className="text-center">
						Sign In
					</CardTitle>
					<CardDescription className="text-sm text-center text-accent-foreground">
						Use email or service, to create account
					</CardDescription>
				</CardHeader>
				{ !!error && (
					<div className="bg-destructive/15 p-3 rounded-md flex items-center gap-x-2 text-sm text-destructive mb-6">
						<TriangleAlert />
						<p>{error}</p>
					</div>
				)}
				<CardContent className="px-2 sm:px-6">
					<form onSubmit={handleSubmit} className="space-y-3">
						<Input 
							type="email"
							disabled={pending}
							placeholder="Email"
							value={email}
							onChange={(e)=>{setEmail(e.target.value)}}
							required
						/>
						<Input 
							type="password"
							disabled={pending}
							placeholder="password"
							value={password}
							onChange={(e)=>{setPassword(e.target.value)}}
							required
						/>
						
						<Button className="w-full" size="lg" disabled={pending}>
							Login
						</Button>
					</form>
					<Separator />
					<div className="flex my-2 pt-2 justify-evenly mx-auto items-center">
						<Button
							disabled={false}
							onClick={(e)=>handleProvider(e, "google")}
							variant="outline"
							size="lg"
							className="bg-slate-300 hover:bg-slate-400 hover:scale-100"
						>
							<FcGoogle className="size-8 left-2.5 top-2.5" />
						</Button>
						<Button
							disabled={false}
							onClick={(e)=>handleProvider(e, "github")}
							variant="outline"
							size="lg"
							className="bg-slate-300 hover:bg-slate-400 hover:scale-100"
						>
							<FaGithub className="size-8 left-2.5 top-2.5" />
						</Button>
					</div>
					<p className="text-center text-sm mt-4 text-muted-foreground">
						Already have an account? 
						<Link className="text-sky-700 hover:underline cursor-pointer" href="sign-up"> Sign Up</Link>
					</p>
				</CardContent>
			</Card>
		</div>
	)
}

export default SignUp