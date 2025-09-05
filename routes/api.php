<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use App\Models\Board;
use App\Models\Column;
use App\Models\Card;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

function makeToken($length = 10)
{
    $s = '';
    for ($i = 0; $i < $length; $i++) {
        $s .= random_int(0, 9);
    }
    return $s;
}

/**
 * Cria registro na tabela de tokens e retorna o token em claro
 */
function issueToken($userId, $name, $abilities, $ttlMinutes)
{
    $tokenPlain = makeToken();                     // ex: "5829103746"
    $hashed = hash('sha256', $tokenPlain);
    $now = Carbon::now();
    $exp = $now->copy()->addMinutes($ttlMinutes);

    DB::table('personal_access_tokens')->insert([
        'tokenable_type' => User::class,
        'tokenable_id' => $userId,
        'name' => $name, // "access" ou "refresh"
        'token' => $hashed,
        'abilities' => json_encode($abilities),
        'expires_at' => $exp,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    return ['plain' => $tokenPlain, 'expires_at' => $exp->toIso8601String()];
}

/**
 * Valida token do header Authorization
 */
function checkAccess(Request $request, $ability = null)
{
    $tokenPlain = $request->bearerToken();
    if (!$tokenPlain)
        return null;

    $token = DB::table('personal_access_tokens')->where('token', hash('sha256', $tokenPlain))->first();
    if (!$token)
        return null;

    if ($token->expires_at && Carbon::parse($token->expires_at)->isPast()) {
        DB::table('personal_access_tokens')->where('id', $token->id)->delete();
        return null;
    }

    $abilities = json_decode($token->abilities ?: '[]', true);
    if ($ability && !in_array($ability, $abilities) && !in_array('*', $abilities)) {
        return null;
    }

    return $token;
}

Route::post('/login', function (Request $request) {
    $data = $request->validate([
        'email' => ['required', 'email'],
        'password' => ['required', 'string'],

    ]);


    $user = User::where('email', $data['email'])->first();
    if (!$user || !Hash::check($data['password'], $user->password)) {
        return response()->json(['message' => 'Credenciais inválidas'], 401);
    }

    $access = issueToken($user->id, 'access', ['*'], 60);        // 60 min
    $refresh = issueToken($user->id, 'refresh', ['refresh'], 20160); // 14 dia

    return response()->json([
        'access_token' => $access['plain'],
        'refresh_token' => $refresh['plain'],
        'expires_in' => 60 * 60,
        'user' => $user,
    ]);
});


Route::post('/refresh', function (Request $request) {
    $data = $request->validate(['refresh_token' => 'required|string']);
    $token = DB::table('personal_access_tokens')->where('token', hash('sha256', $data['refresh_token']))->first();
    if (!$token)
        return response()->json(['message' => 'Refresh inválido'], 401);

    if ($token->expires_at && Carbon::parse($token->expires_at)->isPast()) {
        return response()->json(['message' => 'Refresh expirado'], 401);
    }

    // apaga refresh antigo
    DB::table('personal_access_tokens')->where('id', $token->id)->delete();

    $access = issueToken($token->tokenable_id, 'access', ['*'], 60);
    $refresh = issueToken($token->tokenable_id, 'refresh', ['refresh'], 20160);

    return response()->json([
        'access_token' => $access['plain'],
        'refresh_token' => $refresh['plain'],
        'expires_in' => 60 * 60,
    ]);
});

Route::post('/logout', function (Request $request) {
    $token = checkAccess($request);
    if (!$token)
        return response()->json(['message' => 'Não autenticado'], 401);

    DB::table('personal_access_tokens')->where('id', $token->id)->delete();
    return response()->json(['message' => 'Logout ok']);
});


Route::get('/boards/{id}', function ($id) {
    $board = Board::findOrFail($id);
    $column = Column::where('board_id', $board->id)->get();
    $card = Card::where('board_id', $board->id)->get();

    $response = ['board' => $board, 'column' => $column, 'card' => $card];
    return response()->json($response);
});


Route::get('/boards', function(){
    return Board::all();

});

Route::get('/cards/{id}', function($id) {
    return Card::findOrFail($id);
});



// Boards com TOKEM

Route::post('/boards', function (Request $request) {

    $token = checkAccess($request);
    if (!$token) {
        return response()->json(['message' => 'Não autenticado.'], 401);

    }

    $data = $request->validate([
        'title' => ['required', 'string', 'max:80'],
        'owner_id' => ['required', 'int'],
        'description' => ['required', 'string'],
    ]);

    $board = new Board();
    $board->title = $data['title'];
    $board->owner_id = $data['owner_id'];
    $board->description = $data['description'];
    $board->save();

    return response()->json($board, 201);
});


Route::match(['patch'], '/boards/{id}', function (Request $request, $id) {

    $token = checkAccess($request);
    if (!$token)
        return response()->json(['message' => 'Não autenticado.'], 401);

    $board = Board::findOrFail($id);

    $data = $request->validate([
        'title' => ['sometimes', 'required', 'string'],
        'description' => ['sometimes', 'nullable', 'string', 'min:8'],
    ]);

    if (array_key_exists('title', $data))
        $board->title = $data['title'];

    if (array_key_exists('description', $data))
        $board->description = $data['description'];

    $board->save();
    return response()->json($board);
});


Route::delete('/boards/{id}', function ($id) { 
    $board = Board::findOrFail($id);
    $board->delete();
    return response()->noContent();

});


// Colunas Boards com TOKEN


Route::post('/boards/{id}/columns', function (Request $request) {

    $token = checkAccess($request);
    if (!$token) {
        return response()->json(['message' => 'Não autenticado.'], 401);

    }

    $data = $request->validate([
        'board_id' => ['required', 'int'],
        'name' => ['required', 'string', 'max:80'],
        'order' => ['required', 'int'],
        'wip_limit' => ['required', 'int'],
    ]);

    $column = new Column();
    $column->board_id = $data['board_id'];
    $column->name = $data['name'];
    $column->order = $data['order'];
    $column->wip_limit = $data['wip_limit'];
    $column->save();

    return response()->json($column, 201);
});


Route::match(['patch'], '/columns/{id}', function (Request $request, $id) {

    $token = checkAccess($request);
    if (!$token)
        return response()->json(['message' => 'Não autenticado.'], 401);

    $column = Column::findOrFail($id);

 
    $data = $request->validate([
        'board_id' => ['required', 'int'],
        'name' => ['required', 'string', 'max:80'],
        'order' => ['required', 'int'],
        'wip_limit' => ['required', 'int'],
    ]);

    if (array_key_exists('board_id', $data))
        $column->board_id = $data['board_id'];

    if (array_key_exists('name', $data))
        $column->name = $data['name'];

    if (array_key_exists('order', $data))
        $column->order = $data['order'];
    
    if (array_key_exists('wip_limit', $data))
        $column->wip_limit = $data['wip_limit'];

    $column->save();
    return response()->json($column);
});

Route::delete('/columns/{id}', function ($id) { 
    $column = Column::findOrFail($id);
    $column->delete();
    return response()->noContent();

});

// Cards Boards com TOKEN

Route::post('/boards/{id}/cards', function (Request $request) {

    $token = checkAccess($request);
    if (!$token) {
        return response()->json(['message' => 'Não autenticado.'], 401);

    }

    $data = $request->validate([
        'board_id' => ['required', 'int'],
        'column_id' => ['required', 'int'],
        'title' => ['required', 'string', 'max:80'],
        'description' => ['required', 'string'],
        'position' => ['required', 'int'],
        'created_by' => ['required', 'int'],

    ]);
    
    $card = new Card();
    $card->board_id = $data['board_id'];
    $card->column_id = $data['column_id'];
    $card->title = $data['title'];
    $card->description = $data['description'];
    $card->position = $data['position'];
    $card->created_by = $data['created_by'];
    $card->save();

    return response()->json($card, 201);
});


Route::match(['patch'], '/cards/{id}', function (Request $request, $id) {

    $token = checkAccess($request);
    if (!$token)
        return response()->json(['message' => 'Não autenticado.'], 401);

    $card = Card::findOrFail($id);

    $data = $request->validate([
        'board_id' => ['required', 'int'],
        'column_id' => ['required', 'int'],
        'title' => ['required', 'string', 'max:80'],
        'description' => ['required', 'string'],
        'position' => ['required', 'int'],
        'created_by' => ['required', 'int'],

    ]);

    if (array_key_exists('board_id', $data))
        $card->board_id = $data['board_id'];

    if (array_key_exists('column_id', $data))
        $card->column_id = $data['column_id'];

      if (array_key_exists('title', $data))
        $card->title = $data['title'];

        if (array_key_exists('description', $data))
        $card->description = $data['description'];

          if (array_key_exists('position', $data))
        $card->position = $data['position'];

            if (array_key_exists('created_by', $data))
        $card->created_by = $data['created_by'];

    $card->save();
    return response()->json($card);
});

Route::delete('/cards/{id}', function ($id) { 
    $card = Card::findOrFail($id);
    $card->delete();
    return response()->noContent();

});