<?php

namespace App\Http\Controllers\API;

use Illuminate\Http\Request;
use App\Http\Controllers\API\BaseController as BaseController;
use Illuminate\Support\Facades\Auth;
use Validator;
use App\Models\User;
use Hash;

class AuthController extends BaseController
{

    public function signin(Request $request)
    {
        if(!Auth::attempt($request->only("email","password"))){
            return response()->json([
                'message' => 'Invalid login details'
            ], 401);
        }
        $user = User::where('email', $request['email'])->firstOrFail();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
        ]);
    }

    public function signup(Request $request)
    {
        $input = $request->all();
        $validator = Validator::make($input, [
            
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'confirm_password' => 'required|same:password',
        ]);
        if($validator->fails()){
            return response()->json([$validator->messages(), 'status' => 400], 200);
        }

        
        $user = User::create($input);
        
        $user->password = Hash::make($input['password']);
        $user->save();

        $token = $user->createToken('auth_token')->plainTextToken;
        
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
]);
    }

    
}
