let timerInterval;
let seconds = 0;

function startTimer() {
  timerInterval = setInterval(incrementSeconds, 1000);
}

function stopTimer() {
  clearInterval(timerInterval);
}

function resetTimer() {
  stopTimer();
  seconds = 0;
  document.getElementById("timer").innerText = formatTime(seconds);
}

function incrementSeconds() {
  seconds++;
  document.getElementById("timer").innerText = formatTime(seconds);
}

function formatTime(time) {
  let minutes = Math.floor(time / 60);
  let seconds = time % 60;
  return `${padZero(minutes)}:${padZero(seconds)}`;
}

function padZero(number) {
  if (number < 10) {
    return `0${number}`;
  }
  return number;
}