"use client"

import type React from "react"

import { useState } from "react"
import { useParams, useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Eye, EyeOff, Lock, CheckCircle, AlertCircle, Droplets } from "lucide-react"

export default function ResetPasswordPage() {
    const params = useParams()
    const router = useRouter()
    const token = params.token as string

    const [password, setPassword] = useState("")
    const [confirmPassword, setConfirmPassword] = useState("")
    const [showPassword, setShowPassword] = useState(false)
    const [showConfirmPassword, setShowConfirmPassword] = useState(false)
    const [isLoading, setIsLoading] = useState(false)
    const [message, setMessage] = useState("")
    const [isSuccess, setIsSuccess] = useState(false)
    const [error, setError] = useState("")

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError("")
        setMessage("")

        // Validation
        if (!password || !confirmPassword) {
            setError("Please fill in all fields")
            return
        }

        if (password.length < 6) {
            setError("Password must be at least 6 characters long")
            return
        }

        if (password !== confirmPassword) {
            setError("Passwords do not match")
            return
        }

        setIsLoading(true)

        try {
            const response = await fetch(
                `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000"}/reset-password/${token}`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ password }),
                },
            )

            const data = await response.json()

            if (response.ok) {
                setIsSuccess(true)
                setMessage(data.message || "Password reset successful!")

                // Redirect to login page after 3 seconds
                setTimeout(() => {
                    router.push("/login")
                }, 3000)
            } else {
                setError(data.error || "Failed to reset password")
            }
        } catch (err) {
            setError("Network error. Please try again.")
        } finally {
            setIsLoading(false)
        }
    }

    if (isSuccess) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-[#1A1A2E] p-4">
                <Card className="w-full max-w-md bg-[#1A1A2E]/95 backdrop-blur-sm border border-[#FF6F00]/20 rounded-3xl shadow-2xl">
                    <CardHeader className="text-center">
                        <div className="mx-auto w-16 h-16 bg-gradient-to-br from-green-500/20 to-green-600/20 rounded-2xl flex items-center justify-center mb-6 border border-green-500/20">
                            <CheckCircle className="w-8 h-8 text-green-400" />
                        </div>
                        <CardTitle className="text-2xl font-bold text-[#FFFFFF] mb-3">Password Reset Successful!</CardTitle>
                        <CardDescription className="text-[#B0B0B0] font-medium">
                            Your password has been successfully updated. You will be redirected to the login page shortly.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Button 
                            onClick={() => router.push("/")} 
                            className="w-full bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#D45D00] border-0 rounded-lg font-bold py-3 transition-colors duration-200"
                        >
                            Go to Login
                        </Button>
                    </CardContent>
                </Card>
            </div>
        )
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-[#1A1A2E] p-4">
            {/* Header */}
            <div className="fixed top-0 left-0 right-0 bg-[#1A1A2E] shadow-lg border-b border-[#FF6F00]/20 z-50">
                <div className="max-w-7xl mx-auto px-6 py-4">
                    <div className="flex items-center space-x-4">
                        <div className="relative">
                            <div className="w-12 h-12 bg-[#FF6F00] rounded-lg flex items-center justify-center">
                                <Droplets className="w-6 h-6 text-[#1A1A2E]" />
                            </div>
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold text-[#FFFFFF]">OilPro</h1>
                            <p className="text-[#B0B0B0] text-sm">Premium Services</p>
                        </div>
                    </div>
                </div>
            </div>

            <Card className="w-full max-w-md bg-[#1A1A2E]/95 backdrop-blur-sm border border-[#FF6F00]/20 rounded-3xl shadow-2xl mt-20">
                <CardHeader className="text-center">
                    <div className="mx-auto w-16 h-16 bg-gradient-to-br from-[#FF6F00]/20 to-[#D45D00]/20 rounded-2xl flex items-center justify-center mb-6 border border-[#FF6F00]/30">
                        <Lock className="w-8 h-8 text-[#FF6F00]" />
                    </div>
                    <CardTitle className="text-2xl font-bold text-[#FFFFFF] mb-3">Reset Your Password</CardTitle>
                    <CardDescription className="text-[#B0B0B0] font-medium">
                        Enter your new password below to complete the reset process.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="password" className="text-[#FFFFFF] font-medium">New Password</Label>
                            <div className="relative">
                                <Input
                                    id="password"
                                    type={showPassword ? "text" : "password"}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Enter your new password"
                                    className="pr-10 border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0]"
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-[#B0B0B0] hover:text-[#FFFFFF] transition-colors"
                                    disabled={isLoading}
                                >
                                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="confirmPassword" className="text-[#FFFFFF] font-medium">Confirm New Password</Label>
                            <div className="relative">
                                <Input
                                    id="confirmPassword"
                                    type={showConfirmPassword ? "text" : "password"}
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    placeholder="Confirm your new password"
                                    className="pr-10 border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0]"
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-[#B0B0B0] hover:text-[#FFFFFF] transition-colors"
                                    disabled={isLoading}
                                >
                                    {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>

                        {error && (
                            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-red-400 text-sm font-medium">
                                <div className="flex items-center gap-2">
                                    <AlertCircle className="h-4 w-4 flex-shrink-0" />
                                    <span>{error}</span>
                                </div>
                            </div>
                        )}

                        {message && (
                            <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3 text-green-400 text-sm font-medium">
                                <div className="flex items-center gap-2">
                                    <CheckCircle className="h-4 w-4 flex-shrink-0" />
                                    <span>{message}</span>
                                </div>
                            </div>
                        )}

                        <Button 
                            type="submit" 
                            className="w-full bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#D45D00] border-0 rounded-lg font-bold py-3 transition-colors duration-200" 
                            disabled={isLoading}
                        >
                            {isLoading ? "Resetting Password..." : "Reset Password"}
                        </Button>
                    </form>

                    <div className="mt-6 text-center">
                        <p className="text-sm text-[#B0B0B0]">
                            Remember your password?{" "}
                            <button
                                onClick={() => router.push("/")}
                                className="text-[#FF6F00] hover:text-[#D45D00] font-medium transition-colors"
                            >
                                Back to Login
                            </button>
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}