<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Auth;
use Illuminate\Support\Facades\Hash;
use Throwable;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function login(Request $request)
    {

        $validator  =  Validator::make($request->all(),[
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);


        $credentials = $request->only('email', 'password');

        $token = Auth::attempt($credentials);

        if($validator->fails())
        {
            return response()->json([
                'status' => 'error',
                'message' => $validator->errors(),
            ], 403);
        }

        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized Or Invalid Credentials',
            ], 401);
        }

        $user = Auth::user();
        return response()->json([
            'status' => 'success',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }



    public function register(Request $request)
    {
        $validator  =  Validator::make($request->all(),[
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        if($validator->fails())
        {
            return response()->json([
                'status' => 'error',
                'message' => $validator->errors(),
            ], 403);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

       

        $token = Auth::login($user);
        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }


    public function me()
    {
        try{
        return response()->json(auth()->user());
        }
        catch (Throwable $e) {
           
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function logout()
    {
        Auth::logout();

        try{
        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }
    catch (Throwable $e) {
           
        return response()->json(['error' => $e->getMessage()], 500);
    }
    
    }


    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}
