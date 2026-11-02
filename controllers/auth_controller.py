from config.settings import Settings
from models.usuario import Usuario
from models.usuario_dao import UsuarioDAO
from views.auth_view import AuthView

class AuthController:
    """
    Controlador de Autenticación y Gestión de Usuarios.
    Orquesta el inicio de sesión validando que las credenciales no estén vacías
    ni sean incorrectas, y comparando contraseñas mediante hashes SHA-256.
    """

    def __init__(self):
        self.view = AuthView()

    def iniciar_sesion(self) -> Usuario | None:
        """
        Ejecuta el flujo de inicio de sesión antes de permitir el acceso al menú principal.
        Retorna la instancia de Usuario autenticado o None si agota los intentos.
        """
        UsuarioDAO.inicializar_admin_por_defecto()
        max_intentos = Settings.MAX_LOGIN_ATTEMPTS

        for intento in range(1, max_intentos + 1):
            self.view.mostrar_banner_login(intento, max_intentos)
            credenciales = self.view.solicitar_credenciales()
            username = credenciales["username"]
            clave = credenciales["clave"]

            # 1. Validar que las credenciales ingresadas no estén vacías ni tengan formato inválido
            es_valido, mensaje_validacion = Usuario.validar_credenciales_ingreso(username, clave)
            if not es_valido:
                self.view.mostrar_error(f"Validación fallida: {mensaje_validacion}")
                continue

            # 2. Buscar el usuario en la base de datos y verificar su credencial encriptada
            usuario_bd = UsuarioDAO.obtener_por_username(username)
            if usuario_bd is not None and usuario_bd.verificar_credencial(clave):
                self.view.mostrar_bienvenida(usuario_bd)
                return usuario_bd

            self.view.mostrar_error(
                "Credenciales incorrectas: el usuario no existe o la contraseña no coincide."
            )

        self.view.mostrar_error(
            f"Ha superado el número máximo de intentos permitidos ({max_intentos}). "
            "Acceso bloqueado por seguridad."
        )
        return None

    def ejecutar(self, usuario_actual: Usuario | None = None) -> None:
        while True:
            opcion = self.view.mostrar_menu_usuarios()
            if opcion == 1:
                self.registrar_usuario()
            elif opcion == 2:
                self.listar_usuarios()
            elif opcion == 3:
                self.eliminar_usuario(usuario_actual)
            elif opcion == 0:
                self.view.mostrar_mensaje("Saliendo de la gestión de usuarios.")
                break
            else:
                self.view.mostrar_error("Opción no válida.")

    def registrar_usuario(self) -> None:
        datos = self.view.formulario_nuevo_usuario()

        es_valido, msg = Usuario.validar_credenciales_ingreso(datos["username"], datos["clave"])
        if not es_valido:
            self.view.mostrar_error(msg)
            return

        if not datos["nombre_completo"]:
            self.view.mostrar_error("El nombre completo no puede estar vacío.")
            return

        if datos["clave"] != datos["confirmacion"]:
            self.view.mostrar_error("Las contraseñas ingresadas no coinciden.")
            return

        if UsuarioDAO.obtener_por_username(datos["username"]):
            self.view.mostrar_error(f"Ya existe un usuario registrado con el login '{datos['username']}'.")
            return

        try:
            password_encriptada = Usuario.encriptar_credencial(datos["clave"])
            nuevo_usuario = Usuario(
                username=datos["username"],
                password_hash=password_encriptada,
                nombre_completo=datos["nombre_completo"],
                rol=datos["rol"]
            )
            if UsuarioDAO.crear(nuevo_usuario):
                self.view.mostrar_mensaje(
                    f"Usuario '{nuevo_usuario.username}' registrado exitosamente con credencial encriptada."
                )
            else:
                self.view.mostrar_error("No fue posible guardar el usuario en la base de datos.")
        except (ValueError, TypeError) as e:
            self.view.mostrar_error(f"Datos inválidos: {e}")

    def listar_usuarios(self) -> None:
        usuarios = UsuarioDAO.obtener_todos()
        self.view.mostrar_lista_usuarios(usuarios)

    def eliminar_usuario(self, usuario_actual: Usuario | None = None) -> None:
        id_usuario = self.view.solicitar_id_usuario()
        usuario = UsuarioDAO.obtener_por_id(id_usuario)
        if not usuario:
            self.view.mostrar_error("Usuario no encontrado.")
            return

        if usuario_actual and usuario.id_usuario == usuario_actual.id_usuario:
            self.view.mostrar_error("No puede eliminar su propio usuario con la sesión activa.")
            return

        if self.view.confirmar_eliminacion(usuario.username):
            if UsuarioDAO.eliminar(id_usuario):
                self.view.mostrar_mensaje(f"Usuario '{usuario.username}' eliminado exitosamente.")
            else:
                self.view.mostrar_error("Error al eliminar el usuario en la base de datos.")
        else:
            self.view.mostrar_mensaje("Operación cancelada.")