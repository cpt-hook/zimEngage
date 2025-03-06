<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            $credentials = $request->validate([
                'national_id' => 'required|string',
                'password' => 'required|string',
            ]);

            Log::info('Login attempt', [
                'national_id' => $credentials['national_id'],
                'connection' => config('database.default'),
                'database' => config('database.connections.pgsql.database')
            ]);

            if (Auth::attempt($credentials)) {
                $user = Auth::user();
                $token = $user->createToken('auth-token')->plainTextToken;

                Log::info('Login successful', ['user_id' => $user->id]);

                return response()->json([
                    'token' => $token,
                    'user' => $user,
                    'message' => 'Login successful'
                ]);
            }

            Log::warning('Login failed - invalid credentials', ['national_id' => $credentials['national_id']]);
            
            return response()->json([
                'message' => 'Invalid credentials'
            ], 401);

        } catch (\Exception $e) {
            Log::error('Login error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'message' => 'An error occurred during login',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            $request->user()->currentAccessToken()->delete();
            return response()->json(['message' => 'Logged out successfully']);
        } catch (\Exception $e) {
            Log::error('Logout error', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'message' => 'An error occurred during logout'
            ], 500);
        }
    }
} 