<?php

namespace Database\Seeders;

use App\Models\Board;
use App\Models\Column;
use App\Models\Card;
use App\Models\User;
use App\Models\MoveHistory;
use Illuminate\Database\Seeder;

class BoardSeeder extends Seeder
{
    public function run(): void
    {
        $admin = User::where('email', 'admin@test.com')->first();
        $joao = User::where('email', 'joao@test.com')->first();
        $maria = User::where('email', 'maria@test.com')->first();

        if (!$admin || !$joao || !$maria) {
            throw new \Exception('Users must be seeded before running BoardSeeder');
        }

        // Verificar se o board já existe
        $board = Board::where('title', 'Projeto Demo')->first();
        if (!$board) {
            $board = Board::create([
                'title' => 'Projeto Demo',
                'description' => 'Board de demonstração para testes da API',
                'owner_id' => $admin->id,
            ]);
        }

        // Criar as 3 colunas padrão (verificar se já existem)
        $todoColumn = Column::where('board_id', $board->id)->where('name', 'To Do')->first();
        if (!$todoColumn) {
            $todoColumn = Column::create([
                'board_id' => $board->id,
                'name' => 'To Do',
                'order' => 1,
                'wip_limit' => 999,
            ]);
        }

        $doingColumn = Column::where('board_id', $board->id)->where('name', 'Doing')->first();
        if (!$doingColumn) {
            $doingColumn = Column::create([
                'board_id' => $board->id,
                'name' => 'Doing',
                'order' => 2,
                'wip_limit' => 3,
            ]);
        }

        $doneColumn = Column::where('board_id', $board->id)->where('name', 'Done')->first();
        if (!$doneColumn) {
            $doneColumn = Column::create([
                'board_id' => $board->id,
                'name' => 'Done',
                'order' => 3,
                'wip_limit' => 999,
            ]);
        }

        // Criar cards de exemplo (verificar se já existem)
        $card1 = Card::where('board_id', $board->id)->where('title', 'Implementar autenticação JWT')->first();
        if (!$card1) {
            $card1 = Card::create([
                'board_id' => $board->id,
                'column_id' => $todoColumn->id,
                'title' => 'Implementar autenticação JWT',
                'description' => 'Configurar sistema de login e logout com tokens JWT',
                'position' => 1,
                'created_by' => $admin->id,
            ]);
        }

        $card2 = Card::where('board_id', $board->id)->where('title', 'Criar endpoints públicos')->first();
        if (!$card2) {
            $card2 = Card::create([
                'board_id' => $board->id,
                'column_id' => $todoColumn->id,
                'title' => 'Criar endpoints públicos',
                'description' => 'Implementar rotas GET para visualização dos boards sem autenticação',
                'position' => 2,
                'created_by' => $admin->id,
            ]);
        }

        $card3 = Card::where('board_id', $board->id)->where('title', 'Validação de WIP Limit')->first();
        if (!$card3) {
            $card3 = Card::create([
                'board_id' => $board->id,
                'column_id' => $doingColumn->id,
                'title' => 'Validação de WIP Limit',
                'description' => 'Implementar validação para impedir criar cards em colunas que atingiram o limite',
                'position' => 1,
                'created_by' => $joao->id,
            ]);
        }

        $card4 = Card::where('board_id', $board->id)->where('title', 'Configurar migrations')->first();
        if (!$card4) {
            $card4 = Card::create([
                'board_id' => $board->id,
                'column_id' => $doneColumn->id,
                'title' => 'Configurar migrations',
                'description' => 'Criar todas as migrations necessárias para o projeto',
                'position' => 1,
                'created_by' => $maria->id,
            ]);
        }

        // Criar histórico inicial (verificar se já existe)
        if (!MoveHistory::where('card_id', $card1->id)->where('type', 'created')->exists()) {
            MoveHistory::logCreated($card1, $admin);
        }
        if (!MoveHistory::where('card_id', $card2->id)->where('type', 'created')->exists()) {
            MoveHistory::logCreated($card2, $admin);
        }
        if (!MoveHistory::where('card_id', $card3->id)->where('type', 'created')->exists()) {
            MoveHistory::logCreated($card3, $joao);
        }
        if (!MoveHistory::where('card_id', $card4->id)->where('type', 'created')->exists()) {
            MoveHistory::logCreated($card4, $maria);
        }

        // Simular uma movimentação (verificar se já existe)
        if (!MoveHistory::where('card_id', $card4->id)->where('type', 'moved')->exists()) {
            MoveHistory::create([
                'card_id' => $card4->id,
                'board_id' => $board->id,
                'from_column_id' => $todoColumn->id,
                'to_column_id' => $doneColumn->id,
                'type' => 'moved',
                'by_user_id' => $maria->id,
                'at' => now()->subHours(2),
            ]);
        }

        // Board adicional para testes (verificar se já existe)
        $board2 = Board::where('title', 'Projeto Pessoal')->first();
        if (!$board2) {
            $board2 = Board::create([
                'title' => 'Projeto Pessoal',
                'description' => 'Meu board particular',
                'owner_id' => $joao->id,
            ]);
        }

        // Colunas para o segundo board (verificar se já existem)
        if (!Column::where('board_id', $board2->id)->where('name', 'To Do')->exists()) {
            Column::create([
                'board_id' => $board2->id,
                'name' => 'To Do',
                'order' => 1,
                'wip_limit' => 5,
            ]);
        }

        if (!Column::where('board_id', $board2->id)->where('name', 'Doing')->exists()) {
            Column::create([
                'board_id' => $board2->id,
                'name' => 'Doing',
                'order' => 2,
                'wip_limit' => 2,
            ]);
        }

        if (!Column::where('board_id', $board2->id)->where('name', 'Done')->exists()) {
            Column::create([
                'board_id' => $board2->id,
                'name' => 'Done',
                'order' => 3,
                'wip_limit' => 999,
            ]);
        }
    }
}