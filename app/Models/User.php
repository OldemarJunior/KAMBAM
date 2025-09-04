<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    public function boards()
    {
        return $this->hasMany(Board::class, 'owner_id');
    }

    public function cards()
    {
        return $this->hasMany(Card::class, 'created_by');
    }

    public function moveHistories()
    {
        return $this->hasMany(MoveHistory::class, 'by_user_id');
    }

    public function tokens()
    {
        return $this->hasMany(PersonalAccessToken::class);
    }

    public function createToken(string $ipAddress = null, string $userAgent = null): array
    {
        // Limpar tokens expirados
        $this->tokens()->where('expires_at', '<', now())->delete();

        // Gerar tokens únicos
        $accessToken = Str::random(64);
        $refreshToken = Str::random(64);

        // Criar registro no banco
        $tokenRecord = $this->tokens()->create([
            'token_hash' => hash('sha256', $accessToken),
            'refresh_token_hash' => hash('sha256', $refreshToken),
            'expires_at' => now()->addHour(), // 1 hora
            'refresh_expires_at' => now()->addDays(14), // 2 semanas
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
        ]);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'expires_at' => $tokenRecord->expires_at->toDateTimeString(),
            'refresh_expires_at' => $tokenRecord->refresh_expires_at->toDateTimeString(),
        ];
    }

    public function refreshToken(string $refreshToken): ?array
    {
        $hashedRefreshToken = hash('sha256', $refreshToken);
        
        $tokenRecord = $this->tokens()
            ->where('refresh_token_hash', $hashedRefreshToken)
            ->where('refresh_expires_at', '>', now())
            ->first();

        if (!$tokenRecord) {
            return null;
        }

        // Gerar novo access token
        $newAccessToken = Str::random(64);
        
        $tokenRecord->update([
            'token_hash' => hash('sha256', $newAccessToken),
            'expires_at' => now()->addHour(),
        ]);

        return [
            'access_token' => $newAccessToken,
            'refresh_token' => $refreshToken, // Refresh token permanece o mesmo
            'expires_at' => $tokenRecord->fresh()->expires_at->toDateTimeString(),
        ];
    }

    public function revokeToken(string $accessToken): bool
    {
        $hashedToken = hash('sha256', $accessToken);
        
        return $this->tokens()
            ->where('token_hash', $hashedToken)
            ->delete() > 0;
    }

    public function revokeAllTokens(): int
    {
        return $this->tokens()->delete();
    }

    public static function findByToken(string $token): ?User
    {
        $hashedToken = hash('sha256', $token);
        
        $tokenRecord = PersonalAccessToken::where('token_hash', $hashedToken)
            ->where('expires_at', '>', now())
            ->with('user')
            ->first();

        if ($tokenRecord) {
            // Atualizar último uso
            $tokenRecord->update(['last_used_at' => now()]);
            return $tokenRecord->user;
        }

        return null;
    }
}