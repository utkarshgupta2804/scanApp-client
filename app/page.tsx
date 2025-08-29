"use client"
import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  Wrench,
  Trophy,
  Truck,
  Award,
  Droplets,
  Settings,
  Loader2,
  CheckCircle,
  XCircle,
  AlertCircle,
  Zap,
  Star,
  Gift,
  Users,
  Mail,
  ArrowLeft,
} from "lucide-react"

// Types
interface User {
  _id: string
  name: string
  username: string
  email: string
  city: string
  points: number
}

interface AuthForm {
  name: string
  city: string
  username: string
  email: string
  password: string
  confirmPassword: string
}

interface ForgotPasswordForm {
  email: string
}

interface ResetPasswordForm {
  password: string
  confirmPassword: string
}

interface Scheme {
  _id: string
  title: string
  description: string
  images?: string
  image?: string
  pointsRequired: number
  createdAt: string
  updatedAt: string
}

interface SchemesResponse {
  success: boolean
  data: Scheme[]
  pagination: {
    currentPage: number
    totalPages: number
    totalSchemes: number
    hasNextPage: boolean
    hasPrevPage: boolean
  }
}

interface ScanResult {
  success: boolean
  message: string
  errorType?: string
  data?: {
    pointsEarned: number
    totalPoints: number
    qrId: string
    customer: {
      id: string
      name: string
      username: string
      points: number
    }
  }
}

// Real QR Scanner using html5-qrcode
interface QRScanner {
  render: (successCallback: (data: string) => void, errorCallback: (error: string) => void) => void
  clear: () => Promise<void>
}

class Html5QrcodeScanner implements QRScanner {
  private elementId: string
  private config: any
  private scanner: any = null

  constructor(elementId: string, config: any, verbose = false) {
    this.elementId = elementId
    this.config = config

    // Dynamically import html5-qrcode
    this.loadScanner()
  }

  private async loadScanner() {
    try {
      // Load html5-qrcode from CDN
      if (!window.Html5QrcodeScanner) {
        const script = document.createElement("script")
        script.src = "https://cdnjs.cloudflare.com/ajax/libs/html5-qrcode/2.3.8/html5-qrcode.min.js"
        document.head.appendChild(script)

        // Wait for script to load
        await new Promise((resolve) => {
          script.onload = resolve
        })
      }
    } catch (error) {
      console.error("Failed to load html5-qrcode:", error)
    }
  }

  render(successCallback: (data: string) => void, errorCallback: (error: string) => void) {
    try {
      if (window.Html5QrcodeScanner) {
        // Mobile-optimized configuration
        const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)

        const config = {
          fps: 10,
          qrbox: isMobile ? { width: 200, height: 200 } : { width: 250, height: 250 },
          aspectRatio: 1.0,
          showTorchButtonIfSupported: true,
          showZoomSliderIfSupported: true,
          defaultZoomValueIfSupported: 2,
          rememberLastUsedCamera: false, // Changed to false to force back camera
          supportedScanTypes: [0, 1], // QR Code and Data Matrix
          ...this.config,
        }

        // Add camera constraints specifically for mobile
        if (isMobile) {
          config.cameraIdOrConfig = { facingMode: "environment" }
        }

        this.scanner = new window.Html5QrcodeScanner(this.elementId, config, false)

        this.scanner.render(successCallback, errorCallback)
      } else {
        // Fallback if library not loaded
        setTimeout(() => this.render(successCallback, errorCallback), 1000)
      }
    } catch (error) {
      console.error("QR Scanner render error:", error)
      errorCallback("Failed to initialize camera scanner")
    }
  }

  async clear() {
    try {
      if (this.scanner) {
        await this.scanner.clear()
        this.scanner = null
      }
    } catch (error) {
      console.error("QR Scanner clear error:", error)
    }
  }
}

// Declare global Html5QrcodeScanner
declare global {
  interface Window {
    Html5QrcodeScanner: any
  }
}

// API Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL
const ADMIN_IMAGE_URL = process.env.NEXT_PUBLIC_ADMIN_IMAGE_URL

// Fixed image URL function
const getImageUrl = (imageUrl: string | null | undefined): string => {
  if (!imageUrl) {
    // Return SVG placeholder for missing images
    return "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAwIiBoZWlnaHQ9IjI1NiIgdmlld0JveD0iMCAwIDQwMCAyNTYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSI0MDAiIGhlaWdodD0iMjU2IiBmaWxsPSIjRjVGNUY1Ii8+CjxyZWN0IHg9IjE1MCIgeT0iOTAiIHdpZHRoPSIxMDAiIGhlaWdodD0iNzYiIHJ4PSI4IiBmaWxsPSIjRDVENUQ1Ii8+Cjx0ZXh0IHg9IjIwMCIgeT0iMTM1IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmaWxsPSIjOTk5IiBmb250LWZhbWlseT0iQXJpYWwsIHNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTQiPk9pbFBybyBTZXJ2aWNlPC90ZXh0Pgo8L3N2Zz4="
  }

  // Since the backend now returns complete URLs, just return them as-is
  return imageUrl
}

const getSchemeIcon = (title: string) => {
  const titleLower = title.toLowerCase()
  if (titleLower.includes("oil") || titleLower.includes("synthetic")) return Droplets
  if (titleLower.includes("support") || titleLower.includes("technical")) return Wrench
  if (titleLower.includes("partnership") || titleLower.includes("program")) return Trophy
  if (titleLower.includes("supply") || titleLower.includes("bulk") || titleLower.includes("fleet")) return Truck
  if (titleLower.includes("filter") || titleLower.includes("solutions")) return Settings
  if (titleLower.includes("quality") || titleLower.includes("assurance")) return Award
  if (titleLower.includes("tune") || titleLower.includes("performance")) return Zap
  return Settings
}

// Enhanced API Service with better error handling and authentication
class ApiService {
  // Get auth token from memory store instead of localStorage
  private static authToken: string | null = null

  // After successful login
  static setAuthToken(token: string): void {
    this.authToken = token

    // Also store in localStorage as backup
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("token", token)
    }

    // Set cookie as well for cross-domain
    if (typeof document !== "undefined") {
      document.cookie = `token=${token}; path=/; max-age=604800` // 7 days
    }
  }

  // Remove auth token from memory
  private static removeAuthToken() {
    this.authToken = null
  }

  // Get auth token from memory OR cookies
  private static getAuthToken(): string | null {
    // First try to get from memory
    if (this.authToken) {
      return this.authToken
    }

    // Check localStorage
    if (typeof localStorage !== "undefined") {
      const lsToken = localStorage.getItem("token")
      if (lsToken) {
        return lsToken
      }
    }

    // Fallback to cookies
    if (typeof document !== "undefined") {
      const cookies = document.cookie.split(";")
      const tokenCookie = cookies.find((cookie) => cookie.trim().startsWith("token="))

      if (tokenCookie) {
        const cookieToken = tokenCookie.split("=")[1].trim()
        return cookieToken
      }
    }

    return null
  }

  static async request(endpoint: string, options: RequestInit = {}, retries = 2): Promise<any> {
    const url = `${API_BASE_URL}${endpoint}`
    const token = this.getAuthToken()

    const defaultHeaders: Record<string, string> = {
      "Content-Type": "application/json",
    }

    // Set both Authorization header AND ensure cookies are sent
    if (token) {
      defaultHeaders.Authorization = `Bearer ${token}`
    }

    const defaultOptions: RequestInit = {
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
      credentials: "include", // This ensures cookies are sent
      ...options,
    }

    try {
      const response = await fetch(url, defaultOptions)
      let data

      const contentType = response.headers.get("content-type")
      if (contentType && contentType.includes("application/json")) {
        data = await response.json()
      } else {
        const text = await response.text()
        data = { error: text || `HTTP error! status: ${response.status}` }
      }

      if (response.status === 401) {
        this.removeAuthToken()
        // Also clear cookie if exists
        if (typeof document !== "undefined") {
          document.cookie = "token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"
        }
        throw new Error("Access token required")
      }

      if (!response.ok) {
        throw new Error(data.error || data.message || `HTTP error! status: ${response.status}`)
      }

      return data
    } catch (error: any) {
      console.error(`Request failed [${endpoint}]:`, error.message)

      if (retries > 0 && !error.message.includes("Access token required")) {
        console.warn(`Retrying... attempts left: ${retries}`)
        await new Promise((resolve) => setTimeout(resolve, 1000))
        return ApiService.request(endpoint, options, retries - 1)
      }

      throw new Error(error.message || "Network request failed")
    }
  }

  static async register(userData: { name: string; city: string; username: string; email: string; password: string }) {
    const response = await this.request("/register", {
      method: "POST",
      body: JSON.stringify(userData),
    })

    // Store token if provided
    if (response.token) {
      this.setAuthToken(response.token)
    }

    return response
  }

  static async login(credentials: { identifier: string; password: string }) {
    const response = await this.request("/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    })

    // Store token if provided
    if (response.token) {
      this.setAuthToken(response.token)
    }

    return response
  }

  static async logout() {
    try {
      await this.request("/logout", {
        method: "POST",
      })
    } catch (error) {
      // Continue with logout even if API call fails
      console.warn("Logout API call failed:", error)
    } finally {
      this.removeAuthToken()
    }
  }

  static async forgotPassword(email: string) {
    return this.request("/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    })
  }

  static async resetPassword(token: string, password: string) {
    return this.request(`/reset-password/${token}`, {
      method: "POST",
      body: JSON.stringify({ password }),
    })
  }

  static async getProfile() {
    return this.request("/profile")
  }

  static async getSchemes(page = 1, limit = 10): Promise<SchemesResponse> {
    return this.request(`/api/schemes?page=${page}&limit=${limit}`)
  }

  static async scanQR(qrData: string): Promise<ScanResult> {
    return this.request("/api/scan-qr", {
      method: "POST",
      body: JSON.stringify({ qrData }),
    })
  }
}

export default function OilProClient() {
  const [isSignedIn, setIsSignedIn] = useState(false)
  const [user, setUser] = useState<User | null>(null)
  const [schemes, setSchemes] = useState<Scheme[]>([])
  const [schemesLoading, setSchemesLoading] = useState(true)
  const [schemesError, setSchemesError] = useState("")
  const [pagination, setPagination] = useState({
    currentPage: 1,
    totalPages: 1,
    totalSchemes: 0,
    hasNextPage: false,
    hasPrevPage: false,
  })
  const [scannerDialog, setScannerDialog] = useState(false)
  const [authDialog, setAuthDialog] = useState(false)
  const [isSignUp, setIsSignUp] = useState(false)
  const [authForm, setAuthForm] = useState<AuthForm>({
    name: "",
    city: "",
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
  })
  const [isLoading, setIsLoading] = useState(false)
  const [authError, setAuthError] = useState("")
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [scannedData, setScannedData] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const scannerRef = useRef<QRScanner | null>(null)
  const [forgotPasswordDialog, setForgotPasswordDialog] = useState(false)
  const [forgotPasswordForm, setForgotPasswordForm] = useState<ForgotPasswordForm>({ email: "" })
  const [forgotPasswordLoading, setForgotPasswordLoading] = useState(false)
  const [forgotPasswordError, setForgotPasswordError] = useState("")
  const [forgotPasswordSuccess, setForgotPasswordSuccess] = useState("")

  const fetchSchemes = async (page = 1) => {
    setSchemesLoading(true)
    setSchemesError("")

    try {
      const response = await ApiService.getSchemes(page, 20)
      setSchemes(response.data)
      setPagination(response.pagination)
    } catch (error: any) {
      console.error("Error fetching schemes:", error)
      setSchemesError(error.message || "Failed to load schemes")
    } finally {
      setSchemesLoading(false)
    }
  }

  useEffect(() => {
    const checkAuthStatus = async () => {
      try {
        const userData = await ApiService.getProfile()
        setUser(userData)
        setIsSignedIn(true)
      } catch (error) {
        setIsSignedIn(false)
        setUser(null)
      }
    }

    checkAuthStatus()
  }, [])

  useEffect(() => {
    fetchSchemes()
  }, [])

  const handleAuth = async () => {
    setIsLoading(true)
    setAuthError("")

    try {
      if (isSignUp) {
        if (!authForm.name.trim()) {
          setAuthError("Name is required")
          return
        }
        if (!authForm.city.trim()) {
          setAuthError("City is required")
          return
        }
        if (!authForm.username.trim()) {
          setAuthError("Username is required")
          return
        }
        if (!authForm.email.trim()) {
          setAuthError("Email is required")
          return
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(authForm.email)) {
          setAuthError("Please enter a valid email address")
          return
        }
        if (!authForm.password) {
          setAuthError("Password is required")
          return
        }
        if (authForm.password !== authForm.confirmPassword) {
          setAuthError("Passwords don't match!")
          return
        }

        await ApiService.register({
          name: authForm.name,
          city: authForm.city,
          username: authForm.username,
          email: authForm.email,
          password: authForm.password,
        })

        const userData = await ApiService.getProfile()
        setUser(userData)
        setIsSignedIn(true)
        setAuthDialog(false)
        resetAuthForm()
      } else {
        if (!authForm.username.trim()) {
          setAuthError("Email or username is required")
          return
        }
        if (!authForm.password) {
          setAuthError("Password is required")
          return
        }

        await ApiService.login({
          identifier: authForm.username,
          password: authForm.password,
        })

        const userData = await ApiService.getProfile()
        setUser(userData)
        setIsSignedIn(true)
        setAuthDialog(false)
        resetAuthForm()
      }
    } catch (error: any) {
      setAuthError(error.message || "Authentication failed")
    } finally {
      setIsLoading(false)
    }
  }

  const handleLogout = async () => {
    try {
      await ApiService.logout()
      setIsSignedIn(false)
      setUser(null)
    } catch (error) {
      console.error("Logout failed:", error)
      setIsSignedIn(false)
      setUser(null)
    }
  }

  const resetAuthForm = () => {
    setAuthForm({
      name: "",
      city: "",
      username: "",
      email: "",
      password: "",
      confirmPassword: "",
    })
    setAuthError("")
  }

  const handleForgotPassword = async () => {
    setForgotPasswordLoading(true)
    setForgotPasswordError("")
    setForgotPasswordSuccess("")

    try {
      if (!forgotPasswordForm.email.trim()) {
        setForgotPasswordError("Email is required")
        return
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailRegex.test(forgotPasswordForm.email)) {
        setForgotPasswordError("Please enter a valid email address")
        return
      }

      const result = await ApiService.forgotPassword(forgotPasswordForm.email)
      setForgotPasswordSuccess("Password reset email sent successfully!")
      setForgotPasswordForm({ email: "" })
    } catch (error: any) {
      setForgotPasswordError(error.message || "Failed to send reset email")
    } finally {
      setForgotPasswordLoading(false)
    }
  }

  const openForgotPasswordDialog = () => {
    setAuthDialog(false)
    setForgotPasswordDialog(true)
    setForgotPasswordError("")
    setForgotPasswordSuccess("")
  }

  const backToLogin = () => {
    setForgotPasswordDialog(false)
    setAuthDialog(true)
    setForgotPasswordForm({ email: "" })
    setForgotPasswordError("")
    setForgotPasswordSuccess("")
  }

  const startScanning = () => {
    if (!isSignedIn) {
      setAuthDialog(true)
      return
    }
    setScannerDialog(true)
    setScanResult(null)
  }

  const reinitializeScanner = () => {
    setScanResult(null)
    setScannedData(null)

    setTimeout(() => {
      const qrReaderElement = document.getElementById("qr-reader")
      if (!qrReaderElement) return

      try {
        if (scannerRef.current) {
          scannerRef.current.clear().catch(() => { })
        }

        scannerRef.current = new Html5QrcodeScanner(
          "qr-reader",
          {
            fps: 10,
            qrbox: { width: 200, height: 200 },
            aspectRatio: 1.0,
          },
          false,
        )

        scannerRef.current.render(
          (decodedText) => {
            handleQRScan(decodedText)
          },
          (error) => {
            if (!error.includes("NotFoundException")) {
              console.log("QR scan error:", error)
            }
          },
        )
      } catch (error) {
        console.error("Failed to reinitialize scanner:", error)
      }
    }, 100)
  }

  const handleQRScan = async (qrData: string) => {
    const scanMetadata = {
      rawData: qrData,
      timestamp: new Date().toISOString(),
      dataLength: qrData.length,
      dataType: detectDataType(qrData),
      parsedData: parseQRData(qrData),
    }

    console.log("[v0] QR scan complete:", scanMetadata)
    setScannedData(JSON.stringify(scanMetadata, null, 2))

    if (scannerRef.current) {
      scannerRef.current.clear().catch(() => { })
      scannerRef.current = null
    }
  }

  const handleSubmitScannedData = async () => {
    if (!scannedData) return

    setIsSubmitting(true)
    try {
      const parsedScannedData = JSON.parse(scannedData)
      const rawQRData = parsedScannedData.rawData

      console.log("[v0] Submitting raw QR data:", rawQRData)

      const result = await ApiService.scanQR(rawQRData)
      setScanResult(result)

      if (result.success && result.data) {
        setUser((prev) => (prev ? { ...prev, points: result.data!.totalPoints } : null))
      }

      if (result.success) {
        setScannedData(null)
      }
    } catch (error: any) {
      console.error("Error submitting QR data:", error)

      let errorMessage = "Failed to process QR code"
      let errorType = "general"

      if (error.message.includes("already been scanned") || error.message.includes("already scanned")) {
        errorMessage = "This QR code has already been redeemed"
        errorType = "already_scanned"
      } else if (error.message.includes("not found")) {
        errorMessage = "Invalid QR code - not found in system"
        errorType = "not_found"
      } else if (error.message.includes("inactive")) {
        errorMessage = "This QR code batch is no longer active"
        errorType = "inactive"
      } else if (error.message.includes("Invalid QR code format")) {
        errorMessage = "Invalid QR code format"
        errorType = "invalid_format"
      }

      setScanResult({
        success: false,
        message: errorMessage,
        errorType: errorType,
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  useEffect(() => {
    if (scannerDialog) {
      const initializeScanner = () => {
        const qrReaderElement = document.getElementById("qr-reader")
        if (!qrReaderElement) {
          setTimeout(initializeScanner, 100)
          return
        }

        try {
          if (scannerRef.current) {
            scannerRef.current.clear().catch(() => { })
          }

          scannerRef.current = new Html5QrcodeScanner(
            "qr-reader",
            {
              fps: 10,
              qrbox: { width: 200, height: 200 },
              aspectRatio: 1.0,
            },
            false,
          )

          scannerRef.current.render(
            (decodedText) => {
              handleQRScan(decodedText)
            },
            (error) => {
              if (!error.includes("NotFoundException")) {
                console.log("QR scan error:", error)
              }
            },
          )
        } catch (error) {
          console.error("Failed to initialize scanner:", error)
        }
      }

      setTimeout(initializeScanner, 100)
    }

    return () => {
      if (scannerRef.current) {
        scannerRef.current.clear().catch(() => { })
        scannerRef.current = null
      }
    }
  }, [scannerDialog])

  const handleRedeem = (scheme: Scheme) => {
    if (user && user.points >= scheme.pointsRequired) {
      const newPoints = user.points - scheme.pointsRequired
      setUser((prev) => (prev ? { ...prev, points: newPoints } : null))
      alert(`Successfully redeemed: ${scheme.title}!`)
    }
  }

  const switchAuthMode = () => {
    setIsSignUp(!isSignUp)
    resetAuthForm()
  }

  const handleLoadMoreSchemes = () => {
    if (pagination.hasNextPage && !schemesLoading) {
      fetchSchemes(pagination.currentPage + 1)
    }
  }

  const handleScannerDialogChange = (open: boolean) => {
    setScannerDialog(open)
    if (!open) {
      setScanResult(null)
      setScannedData(null)
      if (scannerRef.current) {
        scannerRef.current.clear().catch(() => { })
        scannerRef.current = null
      }
    }
  }

  const closeScanResult = () => {
    setScanResult(null)
    setScannedData(null)
    setScannerDialog(false)
  }

  const detectDataType = (data: string): string => {
    if (data.startsWith("http://") || data.startsWith("https://")) return "URL"
    if (data.startsWith("mailto:")) return "Email"
    if (data.startsWith("tel:")) return "Phone"
    if (data.startsWith("wifi:")) return "WiFi"
    if (data.startsWith("geo:")) return "Location"
    if (data.startsWith("BEGIN:VCARD")) return "vCard"
    if (data.startsWith("BEGIN:VEVENT")) return "Calendar Event"

    try {
      JSON.parse(data)
      return "JSON"
    } catch {
      // Not JSON
    }

    if (/^\d+$/.test(data)) return "Numeric"
    if (data.includes("\n") || data.length > 100) return "Text (Multi-line)"

    return "Text"
  }

  const parseQRData = (data: string): any => {
    const type = detectDataType(data)

    switch (type) {
      case "JSON":
        try {
          return JSON.parse(data)
        } catch {
          return { error: "Invalid JSON format" }
        }

      case "URL":
        try {
          const url = new URL(data)
          return {
            protocol: url.protocol,
            hostname: url.hostname,
            pathname: url.pathname,
            search: url.search,
            hash: url.hash,
          }
        } catch {
          return { error: "Invalid URL format" }
        }

      case "WiFi":
        const wifiMatch = data.match(/WIFI:T:([^;]*);S:([^;]*);P:([^;]*);H:([^;]*);?/)
        if (wifiMatch) {
          return {
            type: wifiMatch[1],
            security: wifiMatch[2],
            password: wifiMatch[3],
            hidden: wifiMatch[4] === "true",
          }
        }
        return { error: "Invalid WiFi format" }

      case "Location":
        const geoMatch = data.match(/geo:([^,]+),([^,?]+)/)
        if (geoMatch) {
          return {
            latitude: Number.parseFloat(geoMatch[1]),
            longitude: Number.parseFloat(geoMatch[2]),
          }
        }
        return { error: "Invalid location format" }

      default:
        return {
          length: data.length,
          wordCount: data.split(/\s+/).length,
          hasSpecialChars: /[^a-zA-Z0-9\s]/.test(data),
          preview: data.length > 50 ? data.substring(0, 50) + "..." : data,
        }
    }
  }

  return (
    <div className="min-h-screen bg-[#1A1A2E] transition-all duration-500">
      <header className="bg-[#1A1A2E] shadow-lg sticky top-0 z-50 border-b border-[#FF6F00]/20">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 py-3 sm:py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 sm:space-x-4">
              {/* Logo + Company Name */}
              <img
                src="/sri-ganesh-logo.jpg"
                alt="Sri Ganesh Agencies logo"
                className="h-8 w-8 sm:h-12 sm:w-12 rounded bg-white/5 object-contain"
              />
              <div>
                <h1 className="text-lg sm:text-2xl font-bold text-[#FFFFFF]">Sri Ganesh Agencies</h1>
              </div>
            </div>

            <div className="flex items-center space-x-2 sm:space-x-4">
              {isSignedIn && user && (
                <div className="bg-[#FF6F00]/10 rounded-lg px-2 sm:px-4 py-1 sm:py-2 border border-[#FF6F00]/30">
                  <div className="flex items-center space-x-1 sm:space-x-2">
                    <div className="w-4 h-4 sm:w-6 sm:h-6 bg-[#FF6F00] rounded-full flex items-center justify-center">
                      <Star className="w-2 h-2 sm:w-3 sm:h-3 text-[#1A1A2E]" />
                    </div>
                    <span className="text-[#FFFFFF] font-bold text-sm sm:text-lg">{user.points}</span>
                    <span className="text-[#B0B0B0] text-xs sm:text-sm">pts</span>
                  </div>
                </div>
              )}

              <Button
                onClick={startScanning}
                className="bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#FF6F00]/90 border-0 rounded-lg px-3 sm:px-6 py-2 sm:py-3 font-bold transition-colors duration-200 text-sm sm:text-base"
              >
                <div className="flex items-center space-x-1 sm:space-x-2">
                  <span className="hidden sm:inline">Scan QR</span>
                  <span className="sm:hidden">QR</span>
                </div>
              </Button>

              {isSignedIn && user ? (
                <button
                  onClick={handleLogout}
                  className="text-[#B0B0B0] hover:text-[#FFFFFF] transition-all duration-300 bg-[#FFFFFF]/5 hover:bg-[#FFFFFF]/10 rounded-xl sm:rounded-2xl px-2 sm:px-4 py-1 sm:py-2 hover:scale-105"
                >
                  <div className="flex items-center space-x-1 sm:space-x-2">
                    <div className="w-4 h-4 sm:w-6 sm:h-6 bg-[#00B4D8]/20 rounded-full flex items-center justify-center">
                      <Users className="w-2 h-2 sm:w-3 sm:h-3" />
                    </div>
                    <span className="font-medium text-xs sm:text-base hidden sm:inline">{user.name}</span>
                  </div>
                </button>
              ) : (
                <button
                  onClick={() => setAuthDialog(true)}
                  className="text-[#B0B0B0] hover:text-[#FFFFFF] transition-all duration-300 bg-[#FFFFFF]/5 hover:bg-[#FFFFFF]/10 rounded-xl sm:rounded-2xl px-2 sm:px-4 py-1 sm:py-2 hover:scale-105"
                >
                  <span className="font-medium text-xs sm:text-base">Account</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-3 sm:px-6">
        <section className="py-10 sm:py-20">
          <div className="max-w-7xl mx-auto px-3 sm:px-6">
            <div className="text-center mb-8 sm:mb-16">
              <div className="inline-flex items-center space-x-2 sm:space-x-3 bg-[#FF6F00]/10 px-3 sm:px-6 py-2 sm:py-3 rounded-full mb-4 sm:mb-8 border border-[#FF6F00]/20">
                <Trophy className="w-4 h-4 sm:w-6 sm:h-6 text-[#FF6F00]" />
                <span className="text-[#FF6F00] font-bold text-sm sm:text-lg">Premium Services</span>
              </div>
              <h2 className="text-3xl sm:text-5xl font-bold text-[#FFFFFF] mb-4 sm:mb-6 tracking-tight">
                Redeem Your <span className="text-[#FF6F00]">Rewards</span>
              </h2>
              <p className="text-base sm:text-xl text-[#B0B0B0] max-w-3xl mx-auto font-medium leading-relaxed">
                Transform your loyalty points into premium automotive services and exclusive benefits
              </p>
            </div>

            {schemesLoading ? (
              <div className="flex justify-center">
                <div className="bg-[#FFFFFF]/5 backdrop-blur-sm rounded-2xl sm:rounded-3xl p-6 sm:p-12 border border-[#FF6F00]/20">
                  <Loader2 className="w-8 h-8 sm:w-12 sm:h-12 animate-spin text-[#FF6F00] mx-auto mb-2 sm:mb-4" />
                  <p className="text-[#B0B0B0] text-base sm:text-lg font-medium">Loading services...</p>
                </div>
              </div>
            ) : schemes.length === 0 ? (
              <div className="text-center text-[#B0B0B0] bg-[#FFFFFF]/5 backdrop-blur-sm rounded-2xl sm:rounded-3xl p-8 sm:p-16 border border-[#FF6F00]/20">
                <AlertCircle className="w-12 h-12 sm:w-16 sm:h-16 text-[#00B4D8] mx-auto mb-4 sm:mb-6" />
                <p className="text-lg sm:text-xl font-medium">No services available at the moment</p>
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-8">
                  {schemes.map((scheme, index) => {
                    const IconComponent = getSchemeIcon(scheme.title)
                    const canRedeem = user && user.points >= scheme.pointsRequired

                    return (
                      <Card
                        key={scheme._id}
                        className="bg-white border border-[#B0B0B0]/20 rounded-lg shadow-md hover:shadow-lg transition-shadow duration-300 overflow-hidden flex flex-col"
                        style={{
                          animationDelay: `${index * 100}ms`,
                          animation: "fadeInUp 0.6s ease-out forwards",
                        }}
                      >
                        <div className="relative bg-[#F8F8F8] rounded-t-lg p-2">
                          <div className="border border-gray-200 rounded-lg bg-white">
                            <img
                              src={getImageUrl(scheme.images || scheme.image)}
                              alt={scheme.title}
                              className="w-full h-32 sm:h-56 object-contain p-2 rounded-lg"
                              onError={(e) => {
                                const target = e.target as HTMLImageElement
                                target.src =
                                  "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAwIiBoZWlnaHQ9IjI1NiIgdmlld0JveD0iMCAwIDQwMCAyNTYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSI0MDAiIGhlaWdodD0iMjU2IiBmaWxsPSIjRjVGNUY1Ii8+CjxyZWN0IHg9IjE1MCIgeT0iOTAiIHdpZHRoPSIxMDAiIGhlaWdodD0iNzYiIHJ4PSI4IiBmaWxsPSIjRDVENUQ1Ii8+Cjx0ZXh0IHg9IjIwMCIgeT0iMTM1IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmaWxsPSIjOTk5IiBmb250LWZhbWlseT0iQXJpYWwsIHNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTQiPk9pbFBybyBTZXJ2aWNlPC90ZXh0Pgo8L3N2Zz4="
                              }}
                              loading="lazy"
                            />
                          </div>

                          <div className="absolute top-3 sm:top-6 right-3 sm:right-6 bg-[#FF6F00] text-white rounded-full px-2 sm:px-3 py-1 text-xs font-bold shadow-md">
                            {scheme.pointsRequired} pts
                          </div>
                        </div>

                        <CardContent className="flex flex-col flex-1 p-3 sm:p-4 space-y-2 sm:space-y-4">
                          <CardTitle className="text-base sm:text-lg font-bold text-[#1A1A2E] line-clamp-2">
                            {scheme.title}
                          </CardTitle>

                          <CardDescription className="text-[#666666] text-xs sm:text-sm leading-relaxed line-clamp-3">
                            {scheme.description}
                          </CardDescription>

                          <div className="flex-grow" />

                          <Button
                            onClick={() => handleRedeem(scheme)}
                            disabled={!isSignedIn || !canRedeem}
                            className={`w-full rounded-lg font-bold py-2 sm:py-3 text-xs sm:text-sm transition-colors duration-200 ${canRedeem
                              ? "bg-[#FF6F00] text-white hover:bg-[#00B4D8]"
                              : "bg-[#B0B0B0] text-white cursor-not-allowed"
                              }`}
                          >
                            {!isSignedIn ? (
                              <div className="flex items-center justify-center space-x-1 sm:space-x-2">
                                <Users className="w-3 h-3 sm:w-5 sm:h-5" />
                                <span>Sign in to Redeem</span>
                              </div>
                            ) : canRedeem ? (
                              <div className="flex items-center justify-center space-x-1 sm:space-x-2">
                                <Gift className="w-3 h-3 sm:w-5 sm:h-5" />
                                <span>Redeem Now</span>
                              </div>
                            ) : (
                              <div className="flex items-center justify-center space-x-1 sm:space-x-2">
                                <Star className="w-3 h-3 sm:w-5 sm:h-5" />
                                <span className="text-xs sm:text-sm">
                                  Need {scheme.pointsRequired - (user?.points || 0)} more points
                                </span>
                              </div>
                            )}
                          </Button>
                        </CardContent>
                      </Card>
                    )
                  })}
                </div>

                {pagination.hasNextPage && (
                  <div className="text-center mt-8 sm:mt-16">
                    <Button
                      onClick={handleLoadMoreSchemes}
                      disabled={schemesLoading}
                      className="bg-[#FFFFFF]/5 backdrop-blur-sm text-[#FFFFFF] hover:bg-[#00B4D8] border border-[#FF6F00]/20 rounded-full px-6 sm:px-10 py-3 sm:py-4 font-bold shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105 text-sm sm:text-base"
                    >
                      {schemesLoading ? (
                        <>
                          <Loader2 className="mr-2 sm:mr-3 h-4 w-4 sm:h-5 sm:w-5 animate-spin" />
                          Loading...
                        </>
                      ) : (
                        `Load More Services (${pagination.totalSchemes - schemes.length} remaining)`
                      )}
                    </Button>
                  </div>
                )}
              </>
            )}
          </div>
        </section>
      </main>

      <footer className="mt-20 sm:mt-20 border-t border-[#FF6F00]/20 bg-[#1A1A2E]">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 py-6 sm:py-10 grid grid-cols-1 sm:grid-cols-3 gap-6 sm:gap-8">
          <div className="flex flex-col gap-2">
            <h3 className="text-[#FFFFFF] font-semibold text-base sm:text-lg">Sri Ganesh Agencies</h3>
            <p className="text-[#B0B0B0] text-sm leading-relaxed">908, Anand Market, Yamunanagar 135001</p>
            <a
              href="https://www.google.com/maps?q=908%20Anand%20Market%20Yamunanagar%20135001"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#FF6F00] text-sm font-medium hover:underline"
              aria-label="Open location on Google Maps"
            >
              View on Google Maps
            </a>
          </div>

          <div className="flex flex-col gap-2">
            <h4 className="text-[#FFFFFF] font-semibold text-base sm:text-lg">Contact</h4>
            <a
              href="tel:+919896089897"
              className="text-blue-500 text-sm hover:text-white font-bold underline"
            >
              +91 98960 89897
            </a>
            <a
              href="tel:+917015938614"
              className="text-blue-500 text-sm hover:text-white font-bold underline"
            >
              +91 70159 38614
            </a>


          </div>

          <div className="flex items-start sm:items-center sm:justify-end">
            <div className="text-xs sm:text-sm text-[#B0B0B0]">
              <span className="block sm:text-right">
                © {new Date().getFullYear()} Sri Ganesh Agencies. All rights reserved.
              </span>
            </div>
          </div>
        </div>
      </footer>

      {/* Enhanced QR Scanner Dialog - Mobile Optimized */}
      <Dialog open={scannerDialog} onOpenChange={handleScannerDialogChange}>
        <DialogContent className="sm:max-w-md w-[95vw] max-w-[400px] bg-[#1A1A2E]/95 backdrop-blur-sm border border-[#FF6F00]/20 rounded-2xl sm:rounded-3xl shadow-2xl mx-auto">
          <DialogHeader>
            <DialogTitle className="text-lg sm:text-2xl font-bold text-[#FFFFFF] flex items-center space-x-2 sm:space-x-3">
              <div className="w-8 h-8 sm:w-10 sm:h-10 bg-gradient-to-br from-[#FF6F00] to-[#D45D00] rounded-xl sm:rounded-2xl flex items-center justify-center">
                <Zap className="w-4 h-4 sm:w-5 sm:h-5 text-[#1A1A2E]" />
              </div>
              <span>Scan QR Code</span>
            </DialogTitle>
          </DialogHeader>

          {scanResult ? (
            <div className="space-y-4 sm:space-y-6">
              <div className="text-center">
                {scanResult.success ? (
                  <div className="space-y-4 sm:space-y-6">
                    <CheckCircle className="w-16 h-16 sm:w-20 sm:h-20 text-green-500 mx-auto" />
                    <div>
                      <h3 className="text-lg sm:text-xl font-bold text-green-400 mb-2 sm:mb-3">
                        QR Code Processed Successfully!
                      </h3>
                      <p className="text-[#B0B0B0] mb-4 sm:mb-6 font-medium text-sm sm:text-base">
                        {scanResult.message}
                      </p>
                      {scanResult.data && (
                        <div className="bg-[#FF6F00]/10 p-4 sm:p-6 rounded-xl sm:rounded-2xl space-y-2 sm:space-y-3 border border-[#FF6F00]/20">
                          <div className="flex justify-between items-center">
                            <span className="text-xs sm:text-sm text-[#B0B0B0] font-medium">Points Earned:</span>
                            <span className="font-bold text-green-400 text-base sm:text-lg">
                              +{scanResult.data.pointsEarned}
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-xs sm:text-sm text-[#B0B0B0] font-medium">Total Points:</span>
                            <span className="font-bold text-[#FFFFFF] text-base sm:text-lg">
                              {scanResult.data.totalPoints}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4 sm:space-y-6">
                    {scanResult.errorType === "already_scanned" ? (
                      <AlertCircle className="w-16 h-16 sm:w-20 sm:h-20 text-yellow-500 mx-auto" />
                    ) : (
                      <XCircle className="w-16 h-16 sm:w-20 sm:h-20 text-[#D32F2F] mx-auto" />
                    )}
                    <div>
                      <h3
                        className={`text-lg sm:text-xl font-bold mb-2 sm:mb-3 ${scanResult.errorType === "already_scanned" ? "text-yellow-400" : "text-[#D32F2F]"
                          }`}
                      >
                        {scanResult.errorType === "already_scanned" ? "Already Redeemed" : "Error"}
                      </h3>
                      <p className="text-[#B0B0B0] font-medium text-sm sm:text-base">{scanResult.message}</p>
                    </div>
                  </div>
                )}
              </div>

              <div className="flex space-x-2 sm:space-x-3">
                <Button
                  onClick={closeScanResult}
                  className="flex-1 bg-[#B0B0B0] text-[#FFFFFF] hover:bg-[#737373] border-0 rounded-lg font-bold py-2 sm:py-3 text-sm sm:text-base"
                >
                  Close
                </Button>

                {!scanResult.success &&
                  (scanResult.errorType === "already_scanned" || scanResult.errorType === "not_found") && (
                    <Button
                      onClick={reinitializeScanner}
                      className="flex-1 bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#D45D00] border-0 rounded-lg font-bold py-2 sm:py-3 text-sm sm:text-base"
                    >
                      Scan Another
                    </Button>
                  )}
              </div>
            </div>
          ) : scannedData ? (
            <div className="space-y-4 sm:space-y-6">
              <div className="text-center">
                <CheckCircle className="w-12 h-12 sm:w-16 sm:h-16 text-blue-400 mx-auto mb-3 sm:mb-4" />
                <h3 className="text-lg sm:text-xl font-bold text-[#FFFFFF] mb-2 sm:mb-3">
                  QR Code Scanned Successfully!
                </h3>
              </div>
              <div className="flex space-x-2 sm:space-x-3">
                <Button
                  onClick={handleSubmitScannedData}
                  disabled={isSubmitting}
                  className="flex-1 bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#D45D00] border-0 rounded-lg font-bold py-2 sm:py-3 text-sm sm:text-base"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="mr-1 sm:mr-2 h-3 w-3 sm:h-4 sm:w-4 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    "Get Points"
                  )}
                </Button>
                <Button
                  onClick={reinitializeScanner}
                  disabled={isSubmitting}
                  className="flex-1 bg-[#B0B0B0] text-[#FFFFFF] hover:bg-[#737373] border-0 rounded-lg font-bold py-2 sm:py-3 text-sm sm:text-base"
                >
                  Scan Again
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4 sm:space-y-6">
              <div
                id="qr-reader"
                className="w-full min-h-[250px] sm:min-h-[300px] rounded-xl sm:rounded-2xl overflow-hidden bg-white qr-scanner-container"
              ></div>

              <div className="text-center">
                <div className="flex items-center justify-center space-x-1 sm:space-x-2 text-xs sm:text-sm text-[#FFFFFF] mb-3 sm:mb-4 font-medium">
                  <AlertCircle className="w-3 h-3 sm:w-4 sm:h-4" />
                  <span>Position the QR code within the scanning area</span>
                </div>
              </div>

              <Button
                onClick={() => setScannerDialog(false)}
                className="w-full bg-[#B0B0B0] text-[#FFFFFF] hover:bg-[#737373] border-0 rounded-lg font-bold py-2 sm:py-3 text-sm sm:text-base"
              >
                Cancel
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Enhanced Auth Dialog - Mobile Optimized */}
      <Dialog open={authDialog} onOpenChange={setAuthDialog}>
        <DialogContent className="sm:max-w-md w-[95vw] max-w-[400px] bg-[#1A1A2E]/95 backdrop-blur-sm border border-[#FF6F00]/20 rounded-2xl sm:rounded-3xl shadow-2xl mx-auto">
          <DialogHeader>
            <DialogTitle className="text-lg sm:text-2xl font-bold text-[#FFFFFF] flex items-center space-x-2 sm:space-x-3">
              <div className="w-8 h-8 sm:w-10 sm:h-10 bg-gradient-to-br from-[#FF6F00] to-[#D45D00] rounded-xl sm:rounded-2xl flex items-center justify-center">
                <Users className="w-4 h-4 sm:w-5 sm:h-5 text-[#1A1A2E]" />
              </div>
              <span>{isSignUp ? "Create Account" : "Sign In"}</span>
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4 sm:space-y-6">
            {authError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-2 sm:p-3 text-red-400 text-xs sm:text-sm font-medium">
                {authError}
              </div>
            )}

            <div className="space-y-3 sm:space-y-4">
              {isSignUp && (
                <>
                  <Input
                    type="text"
                    value={authForm.name}
                    onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })}
                    placeholder="Your full name"
                    className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0] text-sm sm:text-base h-10 sm:h-12"
                    disabled={isLoading}
                  />
                  <Input
                    type="text"
                    value={authForm.city}
                    onChange={(e) => setAuthForm({ ...authForm, city: e.target.value })}
                    placeholder="Your city"
                    className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0] text-sm sm:text-base h-10 sm:h-12"
                    disabled={isLoading}
                  />
                  <Input
                    type="email"
                    value={authForm.email}
                    onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                    placeholder="Your email address"
                    className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0] text-sm sm:text-base h-10 sm:h-12"
                    disabled={isLoading}
                  />
                </>
              )}
              <Input
                type="text"
                value={authForm.username}
                onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                placeholder={isSignUp ? "Username" : "Email or Username"}
                className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0] text-sm sm:text-base h-10 sm:h-12"
                disabled={isLoading}
              />

              <Input
                type="password"
                value={authForm.password}
                onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                placeholder="Password"
                className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0] text-sm sm:text-base h-10 sm:h-12"
                disabled={isLoading}
              />

              {isSignUp && (
                <Input
                  type="password"
                  value={authForm.confirmPassword}
                  onChange={(e) => setAuthForm({ ...authForm, confirmPassword: e.target.value })}
                  placeholder="Confirm password"
                  className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0] text-sm sm:text-base h-10 sm:h-12"
                  disabled={isLoading}
                />
              )}
            </div>

            <Button
              onClick={handleAuth}
              disabled={isLoading}
              className="w-full bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#D45D00] border-0 rounded-lg font-bold py-2 sm:py-3 transition-colors duration-200 text-sm sm:text-base"
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-1 sm:mr-2 h-3 w-3 sm:h-4 sm:w-4 animate-spin" />
                  {isSignUp ? "Creating..." : "Signing In..."}
                </>
              ) : isSignUp ? (
                "Create Account"
              ) : (
                "Sign In"
              )}
            </Button>

            <button
              onClick={switchAuthMode}
              disabled={isLoading}
              className="w-full text-xs sm:text-sm text-[#B0B0B0] hover:text-[#FFFFFF] transition-colors font-bold"
            >
              {isSignUp ? "Already have an account? Sign In" : "Don't have an account? Sign Up"}
            </button>
            {!isSignUp && (
              <button
                onClick={openForgotPasswordDialog}
                disabled={isLoading}
                className="text-xs sm:text-sm text-[#FF6F00] hover:text-[#D45D00] transition-colors font-medium"
              >
                Forgot your password?
              </button>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Forgot Password Dialog */}
      <Dialog open={forgotPasswordDialog} onOpenChange={setForgotPasswordDialog}>
        <DialogContent className="sm:max-w-md bg-[#1A1A2E]/95 backdrop-blur-sm border border-[#FF6F00]/20 rounded-3xl shadow-2xl">
          <DialogHeader>
            <DialogTitle className="text-2xl font-bold text-[#FFFFFF] flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-[#FF6F00] to-[#D45D00] rounded-2xl flex items-center justify-center">
                <Mail className="w-5 h-5 text-[#1A1A2E]" />
              </div>
              <span>Reset Password</span>
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-6">
            {forgotPasswordError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-red-400 text-sm font-medium">
                {forgotPasswordError}
              </div>
            )}

            {forgotPasswordSuccess && (
              <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3 text-green-400 text-sm font-medium">
                {forgotPasswordSuccess}
              </div>
            )}

            <div className="space-y-4">
              <p className="text-[#B0B0B0] text-sm">
                Enter your email address and we'll send you a link to reset your password.
              </p>

              <Input
                type="email"
                value={forgotPasswordForm.email}
                onChange={(e) => setForgotPasswordForm({ email: e.target.value })}
                placeholder="Your email address"
                className="border-[#FF6F00]/20 rounded-lg bg-[#FFFFFF]/5 backdrop-blur-sm font-medium text-[#FFFFFF] placeholder:text-[#B0B0B0]"
                disabled={forgotPasswordLoading}
              />
            </div>

            <div className="flex space-x-3">
              <Button
                onClick={backToLogin}
                disabled={forgotPasswordLoading}
                className="flex-1 bg-[#B0B0B0] text-[#FFFFFF] hover:bg-[#737373] border-0 rounded-lg font-bold py-3"
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back
              </Button>

              <Button
                onClick={handleForgotPassword}
                disabled={forgotPasswordLoading}
                className="flex-1 bg-[#FF6F00] text-[#1A1A2E] hover:bg-[#D45D00] border-0 rounded-lg font-bold py-3"
              >
                {forgotPasswordLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Sending...
                  </>
                ) : (
                  <>
                    <Mail className="w-4 h-4 mr-2" />
                    Send Reset Link
                  </>
                )}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <style jsx>{`
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </div>
  )
}
