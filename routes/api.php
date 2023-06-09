<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::group([ "middleware" => "auth:sanctum"], function () {
    Route::get('/me', function (Request $request) {
        return $request->user();
    });
});

Route::get("/", function (Request $request) {
    return "Home";
})->name("home");

Route::post('/auth/login', [AuthController::class, 'loginUser']);
Route::post('/auth/signup', [AuthController::class, 'createUser']);
