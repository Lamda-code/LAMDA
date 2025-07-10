// admin/gestion_etudiants.php - Formulaire d'ajout
<form method="post" action="traitement_ajout_etudiant.php">
    <div class="mb-3">
        <label class="form-label">Matricule</label>
        <input type="text" name="matricule" required class="form-control">
    </div>
    <div class="mb-3">
        <label class="form-label">Nom</label>
        <input type="text" name="nom" required class="form-control">
    </div>
    <!-- Ajouter les autres champs -->
    <div class="mb-3">
        <label class="form-label">Formation</label>
        <select name="id_formation" required class="form-select">
            <?php
            $formations = $conn->query("SELECT * FROM formations");
            while ($f = $formations->fetch()) {
                echo "<option value='" . $f['id_formation'] . "'>" . $f['libelle_formation'] . "</option>";
            }
            ?>
        </select>
    </div>
    <button type="submit" class="btn btn-success">Enregistrer</button>
</form>

// traitement_ajout_etudiant.php
<?php
session_start();
if (!isset($_SESSION['admin_id'])) {
    header("Location: ../connexion.php");
    exit();
}

require_once '../includes/config.php';

$matricule = $_POST['matricule'];
$nom = $_POST['nom'];
// Récupérer les autres champs
$id_formation = $_POST['id_formation'];
$mot_de_passe = password_hash($matricule, PASSWORD_DEFAULT); // Mot de passe par défaut = matricule

try {
    $stmt = $conn->prepare("INSERT INTO etudiants VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([$matricule, $nom, $prenom, $adresse, $telephone, $id_formation, $mot_de_passe]);

    $_SESSION['success'] = "Étudiant ajouté avec succès";
    header("Location: gestion_etudiants.php");
} catch (PDOException $e) {
    $_SESSION['error'] = "Erreur: " . $e->getMessage();
    header("Location: gestion_etudiants.php");
}
?>
// etudiant/modifier_mdp.php
<?php
session_start();
if (!isset($_SESSION['etudiant_matricule'])) {
    header("Location: ../connexion.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    require_once '../includes/config.php';

    $ancien_mdp = $_POST['ancien_mdp'];
    $nouveau_mdp = $_POST['nouveau_mdp'];
    $confirmation = $_POST['confirmation'];

    // Vérifier l'ancien mot de passe
    $stmt = $conn->prepare("SELECT mot_de_passe FROM etudiants WHERE matricule = ?");
    $stmt->execute([$_SESSION['etudiant_matricule']]);
    $etudiant = $stmt->fetch();

    if (password_verify($ancien_mdp, $etudiant['mot_de_passe'])) {
        if ($nouveau_mdp == $confirmation) {
            $hash = password_hash($nouveau_mdp, PASSWORD_DEFAULT);
            $update = $conn->prepare("UPDATE etudiants SET mot_de_passe = ? WHERE matricule = ?");
            $update->execute([$hash, $_SESSION['etudiant_matricule']]);

            $_SESSION['success'] = "Mot de passe modifié avec succès";
        } else {
            $_SESSION['error'] = "Les nouveaux mots de passe ne correspondent pas";
        }
    } else {
        $_SESSION['error'] = "Ancien mot de passe incorrect";
    }

    header("Location: modifier_mdp.php");
    exit();
}
?>

<!-- Formulaire HTML -->
<form method="post">
    <div class="mb-3">
        <label class="form-label">Ancien mot de passe</label>
        <input type="password" name="ancien_mdp" required class="form-control">
    </div>
    <div class="mb-3">
        <label class="form-label">Nouveau mot de passe</label>
        <input type="password" name="nouveau_mdp" required class="form-control">
    </div>
    <div class="mb-3">
        <label class="form-label">Confirmation</label>
        <input type="password" name="confirmation" required class="form-control">
    </div>
    <button type="submit" class="btn btn-primary">Modifier</button>
</form>
// admin/gestion_notes.php
<?php
// Vérification admin...
$matieres = $conn->query("SELECT * FROM matieres");
$etudiants = $conn->query("SELECT * FROM etudiants");
?>

<form method="post" action="traitement_note.php">
    <div class="mb-3">
        <label>Étudiant</label>
        <select name="matricule" required class="form-select">
            <?php while ($e = $etudiants->fetch()): ?>
                <option value="<?= $e['matricule'] ?>">
                    <?= $e['nom'] ?> <?= $e['prenom'] ?> (<?= $e['matricule'] ?>)
                </option>
            <?php endwhile; ?>
        </select>
    </div>

    <div class="mb-3">
        <label>Matière</label>
        <select name="code_matiere" required class="form-select">
            <?php while ($m = $matieres->fetch()): ?>
                <option value="<?= $m['code_matiere'] ?>"><?= $m['libelle_matiere'] ?></option>
            <?php endwhile; ?>
        </select>
    </div>

    <div class="mb-3">
        <label>Note</label>
        <input type="number" step="0.01" min="0" max="20" name="note" required class="form-control">
    </div>

    <button type="submit" class="btn btn-primary">Enregistrer</button>
</form>

// traitement_note.php
<?php
session_start();
// Vérification admin...

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    require '../includes/config.php';

    $matricule = $_POST['matricule'];
    $code_matiere = $_POST['code_matiere'];
    $note = $_POST['note'];

    try {
        // Vérifier si la note existe déjà
        $check = $conn->prepare("SELECT * FROM notes WHERE matricule_etudiant = ? AND code_matiere = ?");
        $check->execute([$matricule, $code_matiere]);

        if ($check->rowCount() > 0) {
            // Mise à jour si existe
            $stmt = $conn->prepare("UPDATE notes SET note = ? WHERE matricule_etudiant = ? AND code_matiere = ?");
            $stmt->execute([$note, $matricule, $code_matiere]);
            $message = "Note mise à jour";
        } else {
            // Insertion si nouvelle
            $stmt = $conn->prepare("INSERT INTO notes (matricule_etudiant, code_matiere, note) VALUES (?, ?, ?)");
            $stmt->execute([$matricule, $code_matiere, $note]);
            $message = "Note enregistrée";
        }

        $_SESSION['success'] = $message;
    } catch (PDOException $e) {
        $_SESSION['error'] = "Erreur: " . $e->getMessage();
    }

    header("Location: gestion_notes.php");
    exit();
}
?>
// etudiant/toutes_notes.php
<?php
session_start();
if (!isset($_SESSION['etudiant_matricule'])) {
    header("Location: ../connexion.php");
    exit();
}

require '../includes/config.php';

$matricule = $_SESSION['etudiant_matricule'];
$notes = $conn->prepare("
    SELECT n.note, m.libelle_matiere 
    FROM notes n
    JOIN matieres m ON n.code_matiere = m.code_matiere
    WHERE n.matricule_etudiant = ?
");
$notes->execute([$matricule]);
?>

<h3>Mes notes</h3>
<table class="table table-striped">
    <thead>
        <tr>
            <th>Matière</th>
            <th>Note</th>
        </tr>
    </thead>
    <tbody>
        <?php while ($note = $notes->fetch()): ?>
            <tr>
                <td><?= htmlspecialchars($note['libelle_matiere']) ?></td>
                <td><?= htmlspecialchars($note['note']) ?></td>
            </tr>
        <?php endwhile; ?>
    </tbody>
</table>
// admin/dashboard.php
<?php
session_start();
if (!isset($_SESSION['admin_id'])) {
    header("Location: ../connexion.php");
    exit();
}

require '../includes/config.php';

// Statistiques
$total_etudiants = $conn->query("SELECT COUNT(*) FROM etudiants")->fetchColumn();
$total_formations = $conn->query("SELECT COUNT(*) FROM formations")->fetchColumn();
$total_matieres = $conn->query("SELECT COUNT(*) FROM matieres")->fetchColumn();
?>

<div class="row">
    <div class="col-md-4">
        <div class="card text-white bg-primary mb-3">
            <div class="card-body">
                <h5 class="card-title">Étudiants</h5>
                <p class="card-text display-4"><?= $total_etudiants ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card text-white bg-success mb-3">
            <div class="card-body">
                <h5 class="card-title">Formations</h5>
                <p class="card-text display-4"><?= $total_formations ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card text-white bg-info mb-3">
            <div class="card-body">
                <h5 class="card-title">Matières</h5>
                <p class="card-text display-4"><?= $total_matieres ?></p>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                Derniers étudiants inscrits
            </div>
            <div class="card-body">
                <table class="table">
                    <?php
                    $etudiants = $conn->query("SELECT * FROM etudiants ORDER BY matricule DESC LIMIT 5");
                    while ($e = $etudiants->fetch()):
                    ?>
                        <tr>
                            <td><?= $e['nom'] ?> <?= $e['prenom'] ?></td>
                            <td><?= $e['matricule'] ?></td>
                        </tr>
                    <?php endwhile; ?>
                </table>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                Actions rapides
            </div>
            <div class="card-body">
                <a href="gestion_etudiants.php" class="btn btn-primary m-1">Gérer les étudiants</a>
                <a href="gestion_notes.php" class="btn btn-success m-1">Gérer les notes</a>
                <a href="gestion_formations.php" class="btn btn-info m-1">Gérer les formations</a>
                <a href="ajouter_admin.php" class="btn btn-warning m-1">Ajouter un admin</a>
            </div>
        </div>
    </div>
</div>
<?php
require 'includes/config.php';
require 'includes/fonctions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';

    // Vérifier si l'email existe (pour admin ou étudiant)
    $stmt = $conn->prepare("SELECT email FROM administrateurs WHERE email = ? 
                           UNION SELECT CONCAT(nom, '.', prenom) AS email FROM etudiants WHERE CONCAT(nom, '.', prenom) = ?");
    $stmt->execute([$email, $email]);

    if ($stmt->rowCount() > 0) {
        // Générer un token sécurisé
        $token = bin2hex(random_bytes(32));
        $expires = date("Y-m-d H:i:s", time() + 3600); // 1 heure d'expiration

        // Stocker le token en base
        $stmt = $conn->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$email, password_hash($token, PASSWORD_DEFAULT), $expires]);

        // Envoyer l'email (simulation)
        $reset_link = "https://votresite.com/nouveau_mdp.php?email=" . urlencode($email) . "&token=$token";
        $message = "Cliquez pour réinitialiser : $reset_link";
        send_email($email, "Réinitialisation de mot de passe", $message);

        $_SESSION['success'] = "Un lien de réinitialisation a été envoyé à votre email.";
        header("Location: connexion.php");
        exit();
    } else {
        $_SESSION['error'] = "Aucun compte trouvé avec cet email.";
        header("Location: demande_reset.php");
        exit();
    }
}

function send_email($to, $subject, $message)
{
    // En production, utiliser PHPMailer ou SendGrid
    mail($to, $subject, $message);
}
?>
<?php
session_start();
require_once 'vendor/autoload.php';
require 'includes/config.php';

// Vérifier les permissions
if (!isset($_SESSION['etudiant_matricule']) && !isset($_SESSION['admin_id'])) {
    die("Accès non autorisé");
}

$matricule = $_GET['matricule'] ?? $_SESSION['etudiant_matricule'];

// Récupérer les données
$stmt = $conn->prepare("
    SELECT e.nom, e.prenom, f.libelle_formation, 
           m.libelle_matiere, n.note
    FROM notes n
    JOIN etudiants e ON n.matricule_etudiant = e.matricule
    JOIN matieres m ON n.code_matiere = m.code_matiere
    JOIN formations f ON e.id_formation = f.id_formation
    WHERE n.matricule_etudiant = ?
");
$stmt->execute([$matricule]);
$notes = $stmt->fetchAll();

// Créer le PDF
$pdf->SetCreator('Système de Gestion des Notes');
$pdf->SetAuthor('Votre Université');
$pdf->SetTitle('Relevé de Notes');
$pdf->AddPage();

// Contenu du PDF
$html = '
<h1 style="text-align:center;">Relevé de Notes Officiel</h1>
<h3>Étudiant: ' . $notes[0]['prenom'] . ' ' . $notes[0]['nom'] . '</h3>
<h4>Formation: ' . $notes[0]['libelle_formation'] . '</h4>
<table border="1" cellpadding="5">
    <tr>
        <th width="70%">Matière</th>
        <th width="30%">Note</th>
    </tr>';

foreach ($notes as $note) {
    $html .= '
    <tr>
        <td>' . $note['libelle_matiere'] . '</td>
        <td>' . $note['note'] . '/20</td>
    </tr>';
}

$html .= '</table>';

$pdf->writeHTML($html, true, false, true, false, '');
$pdf->Output('releve_notes_' . $matricule . '.pdf', 'D'); // 'D' pour téléchargement forcé
?>
<?php
session_start();
require '../includes/config.php';

if (!isset($_SESSION['etudiant_matricule'])) {
    header("Location: ../connexion.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $sujet = htmlspecialchars($_POST['sujet']);
    $contenu = htmlspecialchars($_POST['contenu']);
    $destinataire = $_POST['destinataire'];

    try {
        $stmt = $conn->prepare("
            INSERT INTO messages (expediteur_id, destinataire_id, sujet, contenu)
            VALUES (?, ?, ?, ?)
        ");
        $stmt->execute([
            $_SESSION['etudiant_matricule'],
            $destinataire,
            $sujet,
            $contenu
        ]);

        $_SESSION['success'] = "Message envoyé avec succès!";
        header("Location: boite_envoi.php");
        exit();
    } catch (PDOException $e) {
        $_SESSION['error'] = "Erreur: " . $e->getMessage();
        header("Location: envoyer_message.php");
        exit();
    }
}

// Récupérer la liste des admins
$admins = $conn->query("SELECT id_admin, nom FROM administrateurs");
?>
<?php
// ... vérification session ...

$messages = $conn->prepare("
    SELECT m.*, a.nom AS admin_nom
    FROM messages m
    JOIN administrateurs a ON m.destinataire_id = a.id_admin
    WHERE m.expediteur_id = ?
    ORDER BY m.date_envoi DESC
");
$messages->execute([$_SESSION['etudiant_matricule']]);
?>

<div class="container">
    <h2>Messages envoyés</h2>

    <div class="list-group">
        <?php while ($msg = $messages->fetch()): ?>
            <a href="voir_message.php?id=<?= $msg['id'] ?>"
                class="list-group-item list-group-item-action <?= $msg['lu'] ? '' : 'fw-bold' ?>">
                <div class="d-flex w-100 justify-content-between">
                    <h5 class="mb-1"><?= htmlspecialchars($msg['sujet']) ?></h5>
                    <small><?= date('d/m/Y H:i', strtotime($msg['date_envoi'])) ?></small>
                </div>
                <p class="mb-1">À: <?= htmlspecialchars($msg['admin_nom']) ?></p>
            </a>
        <?php endwhile; ?>
    </div>
</div>
<?php
require 'includes/config.php';

$intervalles = ['0-5', '5-10', '10-15', '15-20'];
$data = ['labels' => $intervalles, 'values' => []];

foreach ($intervalles as $intervalle) {
    list($min, $max) = explode('-', $intervalle);
    $stmt = $conn->prepare("
        SELECT COUNT(*) 
        FROM notes 
        WHERE note >= ? AND note < ?
    ");
    $stmt->execute([$min, $max]);
    $data['values'][] = $stmt->fetchColumn();
}

header('Content-Type: application/json');
echo json_encode($data);
?>
<?php
require 'includes/config.php';

// Construire la requête dynamiquement
$sql = "
    SELECT e.matricule, e.nom, e.prenom, f.libelle_formation, 
           m.libelle_matiere, n.note
    FROM etudiants e
    LEFT JOIN notes n ON e.matricule = n.matricule_etudiant
    LEFT JOIN matieres m ON n.code_matiere = m.code_matiere
    LEFT JOIN formations f ON e.id_formation = f.id_formation
    WHERE 1=1
";

$params = [];

if (!empty($_GET['nom'])) {
    $sql .= " AND (e.nom LIKE ? OR e.prenom LIKE ?)";
    $params[] = '%' . $_GET['nom'] . '%';
    $params[] = '%' . $_GET['nom'] . '%';
}

if (!empty($_GET['formation'])) {
    $sql .= " AND e.id_formation = ?";
    $params[] = $_GET['formation'];
}

if (!empty($_GET['matiere'])) {
    $sql .= " AND n.code_matiere = ?";
    $params[] = $_GET['matiere'];
}

if (!empty($_GET['note_min'])) {
    $sql .= " AND n.note >= ?";
    $params[] = $_GET['note_min'];
}

if (!empty($_GET['note_max'])) {
    $sql .= " AND n.note <= ?";
    $params[] = $_GET['note_max'];
}

$sql .= " ORDER BY e.nom, e.prenom, m.libelle_matiere";

$stmt = $conn->prepare($sql);
$stmt->execute($params);
$resultats = $stmt->fetchAll();
?>

<!-- Afficher les résultats -->
<table class="table table-striped">
    <thead>
        <tr>
            <th>Étudiant</th>
            <th>Formation</th>
            <th>Matière</th>
            <th>Note</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($resultats as $row): ?>
            <tr>
                <td><?= $row['nom'] ?> <?= $row['prenom'] ?></td>
                <td><?= $row['libelle_formation'] ?></td>
                <td><?= $row['libelle_matiere'] ?></td>
                <td><?= $row['note'] ?? 'N/A' ?></td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>
// Pour les données rarement mises à jour
$formations = apcu_fetch('liste_formations');
if (!$formations) {
$formations = $conn->query("SELECT * FROM formations")->fetchAll();
apcu_store('liste_formations', $formations, 3600); // Cache 1h
}
// Dans config.php
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
function log_action($action) {
$log = date('Y-m-d H:i:s') . " - " . $_SESSION['user_type'] . " " .
($_SESSION['admin_id'] ?? $_SESSION['etudiant_matricule']) .
" - $action" . PHP_EOL;
file_put_contents('logs/access.log', $log, FILE_APPEND);
}
<?php
$host = "sqlXXX.epizy.com"; // Serveur de l'hébergeur
$dbname = "epiz_XXX_nomdb"; // Nom de la base donnée
$username = "epiz_XXX_user"; // Votre nom d'utilisateur
$password = "votre_mdp_complexe"; // Votre mot de passe

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Erreur DB: " . $e->getMessage());
    die("Une erreur est survenue. Merci de réessayer plus tard.");
}
?>