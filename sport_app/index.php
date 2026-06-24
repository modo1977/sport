<?php
declare(strict_types=1);

session_start();
date_default_timezone_set('Europe/Bratislava');

$pdo = new PDO(
    'mysql:host=localhost;dbname=sport;charset=utf8mb4',
    'root',
    '',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);

$pdo->exec("
    CREATE TABLE IF NOT EXISTS sport_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(80) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        is_admin TINYINT(1) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
");

$columns = $pdo->query("SHOW COLUMNS FROM sport_users LIKE 'is_admin'")->fetch();
if (!$columns) {
    $pdo->exec('ALTER TABLE sport_users ADD is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER password_hash');
}

$columns = $pdo->query("SHOW COLUMNS FROM zapasy_ms2026 LIKE 'cas'")->fetch();
if (!$columns) {
    $pdo->exec('ALTER TABLE zapasy_ms2026 ADD cas TIME NULL AFTER datum');
}

$pdo->exec("
    CREATE TABLE IF NOT EXISTS sport_votes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        match_id INT NOT NULL,
        vote ENUM('home', 'draw', 'away') NOT NULL,
        home_score INT NULL,
        away_score INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_user_match (user_id, match_id),
        CONSTRAINT fk_sport_votes_user FOREIGN KEY (user_id) REFERENCES sport_users(id) ON DELETE CASCADE,
        CONSTRAINT fk_sport_votes_match FOREIGN KEY (match_id) REFERENCES zapasy_ms2026(id) ON DELETE CASCADE
    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
");

$columns = $pdo->query("SHOW COLUMNS FROM sport_votes LIKE 'home_score'")->fetch();
if (!$columns) {
    $pdo->exec('ALTER TABLE sport_votes ADD home_score INT NULL AFTER vote');
}

$columns = $pdo->query("SHOW COLUMNS FROM sport_votes LIKE 'away_score'")->fetch();
if (!$columns) {
    $pdo->exec('ALTER TABLE sport_votes ADD away_score INT NULL AFTER home_score');
}

$pdo->exec("
    CREATE TABLE IF NOT EXISTS sport_match_results (
        match_id INT NOT NULL PRIMARY KEY,
        result ENUM('home', 'draw', 'away') NOT NULL,
        home_score INT NULL,
        away_score INT NULL,
        admin_user_id INT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_sport_results_match FOREIGN KEY (match_id) REFERENCES zapasy_ms2026(id) ON DELETE CASCADE,
        CONSTRAINT fk_sport_results_admin FOREIGN KEY (admin_user_id) REFERENCES sport_users(id) ON DELETE CASCADE
    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
");

$columns = $pdo->query("SHOW COLUMNS FROM sport_match_results LIKE 'home_score'")->fetch();
if (!$columns) {
    $pdo->exec('ALTER TABLE sport_match_results ADD home_score INT NULL AFTER result');
}

$columns = $pdo->query("SHOW COLUMNS FROM sport_match_results LIKE 'away_score'")->fetch();
if (!$columns) {
    $pdo->exec('ALTER TABLE sport_match_results ADD away_score INT NULL AFTER home_score');
}

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function choiceLabel(?string $choice, array $match): string
{
    return match ($choice) {
        'home' => $match['tim_domaci'] ?: 'Domáci',
        'draw' => 'Remíza',
        'away' => $match['tim_hostia'] ?: 'Hostia',
        default => 'Nezadané',
    };
}

function appTimeZone(): DateTimeZone
{
    static $timeZone = null;
    if (!$timeZone) {
        $timeZone = new DateTimeZone('Europe/Bratislava');
    }

    return $timeZone;
}

function matchStart(array $match): ?DateTimeImmutable
{
    if (empty($match['datum'])) {
        return null;
    }

    $time = !empty($match['cas']) ? $match['cas'] : '00:00';
    return new DateTimeImmutable($match['datum'] . ' ' . $time, appTimeZone());
}

function votingDeadline(array $match): ?DateTimeImmutable
{
    $start = matchStart($match);
    if (!$start) {
        return null;
    }

    if (!empty($match['cas'])) {
        return $start->modify('-1 hour');
    }

    return $start;
}

function isVotingOpenForMatch(array $match): bool
{
    $deadline = votingDeadline($match);
    return $deadline && new DateTimeImmutable('now', appTimeZone()) < $deadline;
}

function showRealVoterNames(array $match): bool
{
    $start = matchStart($match);
    if (!$start) {
        return false;
    }

    if (!empty($match['cas'])) {
        return new DateTimeImmutable('now', appTimeZone()) >= $start;
    }

    return date('Y-m-d') >= $match['datum'];
}

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function isAdmin(): bool
{
    return !empty($_SESSION['user']['is_admin']);
}

$error = '';
$notice = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'login') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        if ($username === '' || $password === '') {
            $error = 'Zadajte meno aj heslo.';
        } elseif (mb_strlen($username) > 80) {
            $error = 'Meno je príliš dlhé.';
        } else {
            $stmt = $pdo->prepare('SELECT id, username, password_hash, is_admin FROM sport_users WHERE username = ?');
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user) {
                $adminCount = (int) $pdo->query('SELECT COUNT(*) FROM sport_users WHERE is_admin = 1')->fetchColumn();
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $newUserIsAdmin = $adminCount === 0 ? 1 : 0;
                $stmt = $pdo->prepare('INSERT INTO sport_users (username, password_hash, is_admin) VALUES (?, ?, ?)');
                $stmt->execute([$username, $hash, $newUserIsAdmin]);
                $_SESSION['user'] = [
                    'id' => (int) $pdo->lastInsertId(),
                    'username' => $username,
                    'is_admin' => $newUserIsAdmin,
                ];
                header('Location: index.php');
                exit;
            }

            if (password_verify($password, $user['password_hash'])) {
                $adminCount = (int) $pdo->query('SELECT COUNT(*) FROM sport_users WHERE is_admin = 1')->fetchColumn();
                if ($adminCount === 0) {
                    $stmt = $pdo->prepare('UPDATE sport_users SET is_admin = 1 WHERE id = ?');
                    $stmt->execute([(int) $user['id']]);
                    $user['is_admin'] = 1;
                }

                $_SESSION['user'] = [
                    'id' => (int) $user['id'],
                    'username' => $user['username'],
                    'is_admin' => (int) $user['is_admin'],
                ];
                header('Location: index.php');
                exit;
            }

            $error = 'Nesprávne heslo pre existujúceho používateľa.';
        }
    }

    if ($action === 'vote' && currentUser()) {
        $matchId = (int) ($_POST['match_id'] ?? 0);
        $homeScore = trim((string) ($_POST['home_score'] ?? ''));
        $awayScore = trim((string) ($_POST['away_score'] ?? ''));

        if ($matchId > 0 && ctype_digit($homeScore) && ctype_digit($awayScore)) {
            $homeScore = (int) $homeScore;
            $awayScore = (int) $awayScore;
            $vote = $homeScore > $awayScore ? 'home' : ($homeScore < $awayScore ? 'away' : 'draw');
            $stmt = $pdo->prepare("SELECT datum, TIME_FORMAT(cas, '%H:%i') AS cas FROM zapasy_ms2026 WHERE id = ?");
            $stmt->execute([$matchId]);
            $match = $stmt->fetch();

            if (!$match || !isVotingOpenForMatch($match)) {
                $error = 'Hlasovať sa dá iba pred dňom zápasu.';
                $error = 'Hlasovanie je už uzavreté.';
            } else {
            $stmt = $pdo->prepare('
                INSERT INTO sport_votes (user_id, match_id, vote, home_score, away_score)
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE vote = VALUES(vote), home_score = VALUES(home_score), away_score = VALUES(away_score)
            ');
            $stmt->execute([(int) currentUser()['id'], $matchId, $vote, $homeScore, $awayScore]);
            header('Location: index.php#match-' . $matchId);
            exit;
            }
        }

        if (!$error) {
            $error = 'Hlas sa nepodarilo uložiť.';
        }
    }

    if ($action === 'set_admin' && isAdmin()) {
        $targetUserId = (int) ($_POST['user_id'] ?? 0);
        $makeAdmin = (int) ($_POST['is_admin'] ?? 0) === 1 ? 1 : 0;

        if ($targetUserId <= 0) {
            $error = 'Používateľ sa nepodaril upraviť.';
        } else {
            $adminCount = (int) $pdo->query('SELECT COUNT(*) FROM sport_users WHERE is_admin = 1')->fetchColumn();
            if ($makeAdmin === 0 && $targetUserId === (int) currentUser()['id'] && $adminCount <= 1) {
                $error = 'Nemôžete odobrať posledného admina.';
            } else {
                $stmt = $pdo->prepare('UPDATE sport_users SET is_admin = ? WHERE id = ?');
                $stmt->execute([$makeAdmin, $targetUserId]);
                if ($targetUserId === (int) currentUser()['id']) {
                    $_SESSION['user']['is_admin'] = $makeAdmin;
                }
                header('Location: index.php#admin-users');
                exit;
            }
        }
    }

    if ($action === 'set_time' && isAdmin()) {
        $matchId = (int) ($_POST['match_id'] ?? 0);
        $time = trim((string) ($_POST['cas'] ?? ''));

        if ($matchId <= 0) {
            $error = 'Čas sa nepodarilo uložiť.';
        } elseif ($time !== '' && !preg_match('/^\d{2}:\d{2}$/', $time)) {
            $error = 'Zadajte čas vo formáte HH:MM.';
        } else {
            $timeValue = $time === '' ? null : $time . ':00';
            $stmt = $pdo->prepare('UPDATE zapasy_ms2026 SET cas = ? WHERE id = ?');
            $stmt->execute([$timeValue, $matchId]);
            header('Location: index.php#match-' . $matchId);
            exit;
        }
    }

    if ($action === 'set_result' && isAdmin()) {
        $matchId = (int) ($_POST['match_id'] ?? 0);
        $homeScore = trim((string) ($_POST['result_home_score'] ?? ''));
        $awayScore = trim((string) ($_POST['result_away_score'] ?? ''));

        if ($matchId > 0 && ctype_digit($homeScore) && ctype_digit($awayScore)) {
            $homeScore = (int) $homeScore;
            $awayScore = (int) $awayScore;
            $result = $homeScore > $awayScore ? 'home' : ($homeScore < $awayScore ? 'away' : 'draw');
            $stmt = $pdo->prepare('SELECT datum FROM zapasy_ms2026 WHERE id = ?');
            $stmt->execute([$matchId]);
            $matchDate = $stmt->fetchColumn();

            if ($homeScore > 99 || $awayScore > 99) {
                $error = 'Skóre môže byť od 0 do 99.';
            } elseif (!$matchDate || $matchDate > date('Y-m-d')) {
                $error = 'Výsledok sa dá označiť až v deň zápasu.';
            } else {
                $stmt = $pdo->prepare('
                    INSERT INTO sport_match_results (match_id, result, home_score, away_score, admin_user_id)
                    VALUES (?, ?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                        result = VALUES(result),
                        home_score = VALUES(home_score),
                        away_score = VALUES(away_score),
                        admin_user_id = VALUES(admin_user_id)
                ');
                $stmt->execute([$matchId, $result, $homeScore, $awayScore, (int) currentUser()['id']]);
                header('Location: index.php#match-' . $matchId);
                exit;
            }
        }

        if (!$error) {
            $error = 'Zadajte výsledok ako celé nezáporné čísla.';
        }
    }
}

$user = currentUser();
$matches = [];
$users = [];
$leaderboard = [];
$today = date('Y-m-d');

if ($user) {
    $stmt = $pdo->prepare("
        SELECT
            z.id,
            z.datum,
            TIME_FORMAT(z.cas, '%H:%i') AS cas,
            z.den_label,
            z.skupina,
            z.zapas,
            z.tim_domaci,
            z.tim_hostia,
            result.result AS result_vote,
            result.home_score AS result_home_score,
            result.away_score AS result_away_score,
            GROUP_CONCAT(
                CONCAT(
                    u.username,
                    ': ',
                    CASE
                        WHEN v.home_score IS NOT NULL AND v.away_score IS NOT NULL THEN CONCAT(v.home_score, ':', v.away_score)
                        WHEN v.vote = 'home' THEN COALESCE(z.tim_domaci, 'Domáci')
                        WHEN v.vote = 'draw' THEN 'Remíza'
                        WHEN v.vote = 'away' THEN COALESCE(z.tim_hostia, 'Hostia')
                    END
                )
                ORDER BY u.username
                SEPARATOR '\n'
            ) AS vote_list,
            my_vote.home_score AS my_home_score,
            my_vote.away_score AS my_away_score,
            my_vote.vote AS my_vote
        FROM zapasy_ms2026 z
        LEFT JOIN sport_votes v ON v.match_id = z.id
        LEFT JOIN sport_users u ON u.id = v.user_id
        LEFT JOIN sport_votes my_vote ON my_vote.match_id = z.id AND my_vote.user_id = ?
        LEFT JOIN sport_match_results result ON result.match_id = z.id
        GROUP BY z.id, my_vote.vote, my_vote.home_score, my_vote.away_score, result.result, result.home_score, result.away_score
        ORDER BY z.datum, z.id
    ");
    $stmt->execute([(int) $user['id']]);
    $matches = $stmt->fetchAll();

    $leaderboard = $pdo->query("
        SELECT
            u.username,
            COALESCE(SUM(
                CASE
                    WHEN r.home_score IS NULL OR r.away_score IS NULL OR v.home_score IS NULL OR v.away_score IS NULL THEN 0
                    WHEN v.home_score = r.home_score AND v.away_score = r.away_score THEN 3
                    WHEN SIGN(v.home_score - v.away_score) = SIGN(r.home_score - r.away_score) THEN 1
                    ELSE 0
                END
            ), 0) AS total_points
        FROM sport_users u
        LEFT JOIN sport_votes v ON v.user_id = u.id
        LEFT JOIN sport_match_results r ON r.match_id = v.match_id
        GROUP BY u.id, u.username
        ORDER BY total_points DESC, u.username ASC
    ")->fetchAll();

    if (isAdmin()) {
        $users = $pdo->query('SELECT id, username, is_admin, created_at FROM sport_users ORDER BY username')->fetchAll();
    }
}
?>
<!doctype html>
<html lang="sk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hlasovanie zápasov</title>
    <style>
        :root {
            color-scheme: light;
            --bg: #f5f7fa;
            --surface: #ffffff;
            --text: #172033;
            --muted: #667085;
            --line: #d8dee9;
            --accent: #0f766e;
            --accent-strong: #0b5f59;
            --danger: #b42318;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: var(--bg);
            color: var(--text);
        }

        .page {
            width: min(1680px, calc(100% - 32px));
            margin: 32px auto;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 20px;
        }

        h1 {
            margin: 0;
            font-size: 28px;
            line-height: 1.2;
        }

        .muted {
            color: var(--muted);
        }

        .panel {
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 22px;
            box-shadow: 0 12px 28px rgba(16, 24, 40, 0.08);
        }

        .login {
            width: min(430px, 100%);
            margin: 12vh auto 0;
        }

        label {
            display: block;
            margin: 14px 0 6px;
            font-weight: 700;
        }

        input {
            width: 100%;
            min-height: 42px;
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 9px 11px;
            font: inherit;
        }

        button,
        .button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 38px;
            border: 1px solid var(--accent);
            border-radius: 6px;
            padding: 8px 13px;
            background: var(--accent);
            color: #ffffff;
            font: inherit;
            font-weight: 700;
            text-decoration: none;
            cursor: pointer;
        }

        button:hover,
        .button:hover {
            background: var(--accent-strong);
        }

        .button.secondary {
            border-color: var(--line);
            background: #ffffff;
            color: var(--text);
        }

        .alert {
            margin: 0 0 16px;
            border: 1px solid #fecdca;
            border-radius: 6px;
            padding: 10px 12px;
            background: #fffbfa;
            color: var(--danger);
        }

        .admin-panel {
            margin-bottom: 18px;
        }

        .admin-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 10px;
            margin-top: 14px;
        }

        .user-admin-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 10px;
            background: #ffffff;
        }

        .role {
            display: inline-flex;
            align-items: center;
            min-height: 24px;
            border-radius: 999px;
            padding: 3px 8px;
            background: #e6f4f1;
            color: var(--accent-strong);
            font-size: 12px;
            font-weight: 700;
        }

        .leaderboard-panel {
            margin-bottom: 18px;
        }

        .leaderboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 10px;
            margin-top: 14px;
        }

        .leaderboard-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            border: 1px solid var(--line);
            border-radius: 6px;
            padding: 10px;
            background: #ffffff;
        }

        .points {
            font-weight: 700;
            white-space: nowrap;
        }

        .table-wrap {
            overflow-x: auto;
            background: var(--surface);
            border: 1px solid var(--line);
            border-radius: 8px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1100px;
        }

        th,
        td {
            border-bottom: 1px solid var(--line);
            padding: 11px 12px;
            text-align: left;
            vertical-align: middle;
        }

        th {
            background: #eef2f7;
            font-size: 13px;
            color: #344054;
        }

        tr:last-child td {
            border-bottom: 0;
        }

        .match {
            font-weight: 700;
        }

        .vote-form {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }

        .score-input {
            width: 58px;
            min-height: 38px;
            text-align: center;
        }

        .score-separator {
            font-weight: 700;
            color: var(--muted);
        }

        .vote-button {
            min-width: 76px;
            background: #ffffff;
            color: var(--text);
            border-color: var(--line);
            white-space: nowrap;
        }

        .vote-button.active {
            background: var(--accent);
            border-color: var(--accent);
            color: #ffffff;
        }

        .result-form {
            display: grid;
            gap: 7px;
        }

        .result-text {
            font-weight: 700;
        }

        .time-form {
            display: flex;
            align-items: center;
            gap: 7px;
            min-width: 150px;
        }

        .time-form input {
            width: 92px;
            min-height: 38px;
        }

        .time-form button {
            min-width: 48px;
            padding-inline: 10px;
        }

        .stats {
            display: grid;
            gap: 5px;
            min-width: 170px;
            font-size: 14px;
        }

        .vote-list {
            display: grid;
            gap: 6px;
            min-width: 190px;
            font-size: 14px;
        }

        .vote-list-item {
            padding: 5px 7px;
            border: 1px solid var(--line);
            border-radius: 6px;
            background: #ffffff;
        }

        .vote-list-item.exact-score {
            background: #F5F4A3;
        }

        .vote-list-item.correct-winner {
            background: #D9F8C4;
        }

        .vote-list-item.wrong-pick {
            background: #F3CACC;
        }

        @media (max-width: 700px) {
            .page {
                width: min(100% - 20px, 1680px);
                margin-top: 18px;
            }

            .topbar {
                align-items: flex-start;
                flex-direction: column;
            }

            h1 {
                font-size: 23px;
            }
        }
    </style>
</head>
<body>
<?php if (!$user): ?>
    <main class="page">
        <section class="panel login">
            <h1>Prihlásenie</h1>
            <p class="muted">Pri prvom použití sa účet vytvorí automaticky.</p>
            <?php if ($error): ?>
                <p class="alert"><?= e($error) ?></p>
            <?php endif; ?>
            <form method="post">
                <input type="hidden" name="action" value="login">
                <label for="username">Meno</label>
                <input id="username" name="username" autocomplete="username" required>
                <label for="password">Heslo</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
                <p>
                    <button type="submit">Prihlásiť sa</button>
                </p>
            </form>
        </section>
    </main>
<?php else: ?>
    <main class="page">
        <header class="topbar">
            <div>
                <h1>Hlasovanie k zápasom</h1>
                <div class="muted">
                    Prihlásený používateľ: <?= e($user['username']) ?>
                    <?php if (isAdmin()): ?>
                        <span class="role">Admin</span>
                    <?php endif; ?>
                </div>
            </div>
            <a class="button secondary" href="logout.php">Odhlásiť sa</a>
        </header>

        <?php if ($error): ?>
            <p class="alert"><?= e($error) ?></p>
        <?php endif; ?>

        <?php if (isAdmin()): ?>
            <section class="panel admin-panel" id="admin-users">
                <h2>Admin používatelia</h2>
                <div class="admin-grid">
                    <?php foreach ($users as $appUser): ?>
                        <form class="user-admin-row" method="post">
                            <input type="hidden" name="action" value="set_admin">
                            <input type="hidden" name="user_id" value="<?= (int) $appUser['id'] ?>">
                            <input type="hidden" name="is_admin" value="<?= (int) $appUser['is_admin'] ? 0 : 1 ?>">
                            <div>
                                <strong><?= e($appUser['username']) ?></strong><br>
                                <span class="muted"><?= (int) $appUser['is_admin'] ? 'Admin' : 'Bežný používateľ' ?></span>
                            </div>
                            <button class="button secondary" type="submit">
                                <?= (int) $appUser['is_admin'] ? 'Odobrať' : 'Označiť' ?>
                            </button>
                        </form>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endif; ?>

        <section class="panel leaderboard-panel">
            <h2>Celkové poradie</h2>
            <div class="leaderboard-grid">
                <?php foreach ($leaderboard as $rank => $rankedUser): ?>
                    <div class="leaderboard-item">
                        <span><?= (int) $rank + 1 ?>. <?= e($rankedUser['username']) ?></span>
                        <span class="points"><?= (int) $rankedUser['total_points'] ?> bodov</span>
                    </div>
                <?php endforeach; ?>
            </div>
        </section>

        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>Dátum</th>
                    <th>Čas</th>
                    <th>Skupina</th>
                    <th>Zápas</th>
                    <th>Váš hlas</th>
                    <th>Hlasy ostatných</th>
                    <th>Výsledok</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($matches as $match): ?>
                    <tr id="match-<?= (int) $match['id'] ?>">
                        <td>
                            <?= e($match['den_label']) ?><br>
                            <span class="muted"><?= e($match['datum']) ?></span>
                        </td>
                        <td>
                            <?php if (isAdmin()): ?>
                                <form class="time-form" method="post">
                                    <input type="hidden" name="action" value="set_time">
                                    <input type="hidden" name="match_id" value="<?= (int) $match['id'] ?>">
                                    <input name="cas" type="time" value="<?= e($match['cas']) ?>" aria-label="Čas zápasu">
                                    <button type="submit">OK</button>
                                </form>
                            <?php else: ?>
                                <span class="<?= $match['cas'] ? '' : 'muted' ?>"><?= e($match['cas'] ?: 'Nezadaný') ?></span>
                            <?php endif; ?>
                        </td>
                        <td><?= e($match['skupina']) ?></td>
                        <td class="match"><?= e($match['zapas']) ?></td>
                        <td>
                            <?php if (isVotingOpenForMatch($match)): ?>
                                <form class="vote-form" method="post">
                                    <input type="hidden" name="action" value="vote">
                                    <input type="hidden" name="match_id" value="<?= (int) $match['id'] ?>">
                                    <input class="score-input" name="home_score" type="number" min="0" max="99" value="<?= e($match['my_home_score']) ?>" aria-label="<?= e($match['tim_domaci'] ?: 'Domáci') ?>" required>
                                    <span class="score-separator">:</span>
                                    <input class="score-input" name="away_score" type="number" min="0" max="99" value="<?= e($match['my_away_score']) ?>" aria-label="<?= e($match['tim_hostia'] ?: 'Hostia') ?>" required>
                                    <button type="submit">OK</button>
                                </form>
                            <?php else: ?>
                                <span class="muted">Hlasovanie je uzavreté.</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="vote-list">
                                <?php if ($match['vote_list']): ?>
                                    <?php $showRealNames = showRealVoterNames($match); ?>
                                    <?php foreach (explode("\n", $match['vote_list']) as $index => $voteItem): ?>
                                        <?php
                                            $parts = explode(': ', $voteItem, 2);
                                            $visibleVoteItem = $showRealNames || count($parts) < 2 ? $voteItem : $parts[0];
                                            $voteClass = '';

                                            if (
                                                $showRealNames
                                                && count($parts) === 2
                                                && $match['result_home_score'] !== null
                                                && $match['result_away_score'] !== null
                                                && preg_match('/^(\d+):(\d+)$/', $parts[1], $scoreParts)
                                            ) {
                                                $tipHomeScore = (int) $scoreParts[1];
                                                $tipAwayScore = (int) $scoreParts[2];
                                                $resultHomeScore = (int) $match['result_home_score'];
                                                $resultAwayScore = (int) $match['result_away_score'];
                                                $tipOutcome = $tipHomeScore <=> $tipAwayScore;
                                                $resultOutcome = $resultHomeScore <=> $resultAwayScore;
                                                $points = 0;
                                                if ($tipHomeScore === $resultHomeScore && $tipAwayScore === $resultAwayScore) {
                                                    $points = 3;
                                                    $voteClass = 'exact-score';
                                                } elseif ($tipOutcome === $resultOutcome) {
                                                    $points = 1;
                                                    $voteClass = 'correct-winner';
                                                } else {
                                                    $voteClass = 'wrong-pick';
                                                }

                                                $visibleVoteItem .= ' | počet bodov: ' . $points;
                                            }
                                        ?>
                                        <div class="vote-list-item<?= $voteClass ? ' ' . e($voteClass) : '' ?>"><?= e($visibleVoteItem) ?></div>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <span class="muted">Zatiaľ nikto nehlasoval.</span>
                                <?php endif; ?>
                            </div>
                        </td>
                        <td>
                            <?php if (isAdmin() && $match['datum'] <= $today): ?>
                                <form class="result-form" method="post">
                                    <input type="hidden" name="action" value="set_result">
                                    <input type="hidden" name="match_id" value="<?= (int) $match['id'] ?>">
                                    <div class="vote-form">
                                        <input class="score-input" name="result_home_score" type="number" min="0" max="99" value="<?= e($match['result_home_score']) ?>" aria-label="Skóre <?= e($match['tim_domaci'] ?: 'Domáci') ?>" required>
                                        <span class="score-separator">:</span>
                                        <input class="score-input" name="result_away_score" type="number" min="0" max="99" value="<?= e($match['result_away_score']) ?>" aria-label="Skóre <?= e($match['tim_hostia'] ?: 'Hostia') ?>" required>
                                        <button type="submit">OK</button>
                                    </div>
                                </form>
                            <?php elseif ($match['result_vote']): ?>
                                <span class="result-text">
                                    <?php if ($match['result_home_score'] !== null && $match['result_away_score'] !== null): ?>
                                        <?= e($match['result_home_score']) ?>:<?= e($match['result_away_score']) ?>
                                    <?php else: ?>
                                        <?= e(choiceLabel($match['result_vote'], $match)) ?>
                                    <?php endif; ?>
                                </span>
                            <?php else: ?>
                                <span class="muted"><?= $match['datum'] < $today ? 'Výsledok nie je zadaný.' : 'Čaká sa na zápas.' ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </main>
<?php endif; ?>
</body>
</html>
