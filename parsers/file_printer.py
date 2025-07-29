from .common import GoHelper, log_error, log_info


class PrintFiles(GoHelper):

    def print_files(self):
        try:
            self.init_gopclntab()
        except ValueError:
            log_error("Golang version not supported")
            return

        for fidx in range(self.gopclntab.nfiletab):
            file_name = self.gopclntab.fileName(fidx)
            log_info(file_name.decode('utf-8'))

    def run(self):
        return self.print_files()
