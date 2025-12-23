import child_process
import child_process/stdio

pub fn main() {
  let assert Ok(child_process.Output(0, _)) =
    child_process.new_with_path("treefmt")
    |> child_process.stdio(stdio.inherit())
    |> child_process.run()
}
