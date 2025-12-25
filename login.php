<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// ถ้าล็อกอินแล้วให้ redirect ไป dashboard
if (isLoggedIn()) {
    redirect('dashboard.php');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = cleanInput($_POST['username']);
    $password = $_POST['password'];
    
    if (empty($username) || empty($password)) {
        $error = 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน';
    } else {
        $stmt = $conn->prepare("SELECT id, username, password, full_name, role, status FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            if ($user['status'] === 'inactive') {
                $error = 'บัญชีของคุณถูกระงับการใช้งาน';
            } elseif (password_verify($password, $user['password'])) {
                // บันทึก session
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['role'] = $user['role'];
                
                // อัพเดทเวลาล็อกอินล่าสุด
                $update_stmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $update_stmt->bind_param("i", $user['id']);
                $update_stmt->execute();
                
                setAlert('เข้าสู่ระบบสำเร็จ!', 'success');
                redirect('dashboard.php');
            } else {
                $error = 'รหัสผ่านไม่ถูกต้อง';
            }
        } else {
            $error = 'ไม่พบชื่อผู้ใช้นี้ในระบบ';
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>เข้าสู่ระบบ - ระบบจัดการผู้ใช้</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h2>🔐 เข้าสู่ระบบ</h2>
                <p>ยินดีต้อนรับกลับมา! กรุณาเข้าสู่ระบบเพื่อดำเนินการต่อ</p>
            </div>
            <div class="card-body">
                <?php if (!empty($error)): ?>
                    <div class="alert alert-error">
                        <?php echo $error; ?>
                    </div>
                <?php endif; ?>
                
                <?php 
                $alert = getAlert();
                if ($alert): 
                ?>
                    <div class="alert alert-<?php echo $alert['type']; ?>">
                        <?php echo $alert['message']; ?>
                    </div>
                <?php endif; ?>
                
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="username">ชื่อผู้ใช้หรืออีเมล</label>
                        <input 
                            type="text" 
                            id="username" 
                            name="username" 
                            class="form-control" 
                            placeholder="กรอกชื่อผู้ใช้หรืออีเมล"
                            value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                            required
                        >
                    </div>
                    
                    <div class="form-group">
                        <label for="password">รหัสผ่าน</label>
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            class="form-control" 
                            placeholder="กรอกรหัสผ่าน"
                            required
                        >
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary">เข้าสู่ระบบ</button>
                    </div>
                    
                    <div class="text-center">
                        <p>ยังไม่มีบัญชี? <a href="register.php" class="link">สมัครสมาชิก</a></p>
                    </div>
                </form>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e0e0e0;">
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; font-size: 13px; color: #666;">
                    <strong>🔑 บัญชีทดสอบ:</strong><br>
                    Admin: admin / password123<br>
                    User: user01 / password123<br>
                    Customer: customer01 / password123<br>
                    Employee: employee01 / password123
                </div>
            </div>
        </div>
    </div>
</body>
</html>