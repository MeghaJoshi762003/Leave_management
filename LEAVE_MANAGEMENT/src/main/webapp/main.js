document.addEventListener("DOMContentLoaded", () => {
    let list = document.getElementById("list");
    let list1 = document.getElementById("requests");
    let teamlist=document.getElementById("teams");
    let employees;
    let leaves;
    let user;
    let empleaves;
    getRequest();
    function getStatusBadgeClass(status) {
        switch (status) {
            case 'APPROVED':
                return 'success';
            case 'PENDING':
                return 'warning';
            case 'REJECTED':
                return 'danger';
            default:
                return 'secondary';
        }
    }
    function hideAllSections() {
        document.getElementById('apply').style.display = "none";
        document.getElementById('teams').style.display = "none";
        document.getElementById('requests').style.display = "none";
        document.getElementById('list').style.display = "none";
        document.getElementById('charts').style.display="none";
        document.getElementById("show").style.backgroundColor="transparent"
    }
    document.getElementById("chart").addEventListener('click',function(){
        hideAllSections();
        document.getElementById("charts").style.display = "block";
    })

    document.getElementById("show").addEventListener('click', function () {
        hideAllSections();
        document.getElementById("list").style.display = "block";
        document.getElementById("show").style.backgroundColor='white'
    });

    document.getElementById("leave").addEventListener('click', function () {
        hideAllSections();
        document.getElementById("apply").style.display = "block";
    });

    document.getElementById("request").addEventListener('click', function () {
        hideAllSections();
        document.getElementById("requests").style.display = "block";
    });

    document.getElementById('team').addEventListener('click', function () {
        hideAllSections();
        document.getElementById("teams").style.display = "block";
    });
    document.getElementById("show").click();

    list1.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON') {
            const li = e.target.closest('li');
            const leaveId = li.dataset.index;
            const isAccept = e.target.classList.contains('btn-success');
            const status = isAccept ? 'true' : 'false';

            fetch(`http://localhost:8080/leave_management/request?status=${status}&leaveId=${leaveId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
            }).then(response => {
                if (!response.ok) {
                    console.error('Fetch error:', response.statusText);
                }
                getRequest();
                loadrequests();
            }).catch(error => {
                console.error('Network error:', error);
            });
        }


    });
    document.getElementById('logout').addEventListener('click', function () {
        console.log("enter");
        debugger;
        fetch("http://localhost:8080/leave_management/logout", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
        })
            .then(response => {
                if (response.ok) {
                    // Optionally handle response status or content
                    console.log('Logged out successfully');
                    window.location.href = 'index.html';  // Redirect manually after logout
                } else {
                    console.error('Logout failed:', response.statusText);
                }
            })
            .catch(error => {
                console.error('Network error:', error);
            });
    });

    function loadLeaves() {
        fetch("http://localhost:8080/leave_management/employee", {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
        })
            .then(response => response.json())
            .then(leaves => {
                // console.log(leaves);
                list.innerHTML = '';
                if(leaves!==undefined)
                {
                leaves.forEach((leave) => {
                    // console.log(leave);
                    const li = document.createElement('li');
                    li.className = 'list-group-item leave-list-item';
                    li.dataset.index = leave.id;
                    li.innerHTML = `
                                   <div class="d-flex flex-column flex-md-row w-100">
                    <div class="me-3 mb-3 mb-md-0">
                        <h6 class="leave-type mb-0">Leave Type: <span class="badge bg-info">${leave.leaveType}</span></h6>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>Reason:</strong> ${leave.reason}</p>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>From Date:</strong> ${leave.fromDate}</p>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>To Date:</strong> ${leave.toDate}</p>
                    </div>
                    <div>
                        <p class="mb-0"><strong>Status:</strong> <span class="badge bg-${getStatusBadgeClass(leave.status)}">${leave.status}</span></p>
                    </div>
                </div>`
                    ;
                    list.appendChild(li);
                });}
            });
    }
    let leave_taken;
    let total_count;
    function getRequest(){

        fetch("http://localhost:8080/leave_management/request", {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
        })
            .then(response => response.json())
            .then(requests=>{
                employees=requests.employees;
                leaves=requests.leaves;
                user=requests.emp;
                empleaves=requests.empleaves;
                console.log(empleaves);
                    loadrequests();
                    loadTeam();
                    leave_taken=requests.leave_taken;
                    total_count=requests.total_count;
                    document.getElementById('sick-taken').textContent=leave_taken['SICK']
                    document.getElementById('sick-left').textContent=total_count['SICK']-leave_taken['SICK']
                    document.getElementById('sick-total').textContent=total_count['SICK']

                    document.getElementById('pto-taken').textContent=leave_taken['PTO']
                    document.getElementById('pto-left').textContent=total_count['PTO']-leave_taken['PTO']
                    document.getElementById('pto-total').textContent=total_count['PTO']
                    if(user['gender']==='female'){
                        document.getElementById('maternity-taken').textContent=leave_taken['MATERNITY']
                        document.getElementById('maternity-left').textContent=total_count['MATERNITY']-leave_taken['MATERNITY']
                        document.getElementById('maternity-total').textContent=total_count['MATERNITY']
                        document.getElementById('paternity-taken').textContent=0
                        document.getElementById('paternity-left').textContent=0
                        document.getElementById('paternity-total').textContent=0
                    }
                    else{
                        document.getElementById('paternity-taken').textContent=leave_taken['PATERNITY']
                        document.getElementById('paternity-left').textContent=total_count['PATERNITY']-leave_taken['PATERNITY']
                        document.getElementById('paternity-total').textContent=total_count['PATERNITY']
                        document.getElementById('maternity-taken').textContent=0
                        document.getElementById('maternity-left').textContent=0
                        document.getElementById('maternity-total').textContent=0
                    }

                    document.getElementById('personal-taken').textContent=leave_taken['PERSONAL']
                    document.getElementById('personal-left').textContent=total_count['PERSONAL']-leave_taken['PERSONAL']
                    document.getElementById('personal-total').textContent=total_count['PERSONAL']

                    document.getElementById("name").textContent=user['name'];
                    document.getElementById("username").textContent=user['name'];
                    document.getElementById("email").textContent=requests.email;
                    document.getElementById("phone").textContent=user['phoneNumber'];
                    document.getElementById("gender").textContent=user['gender'];

                    document.getElementById("sick").textContent= 'SICK Leave Left: '+ (total_count['SICK']-leave_taken['SICK']);
                    document.getElementById("pto").textContent= 'PTO Leave Left: '+ (total_count['PTO']-leave_taken['PTO']);
                    document.getElementById("personal").textContent= 'PERSONAL Leave Left: '+ (total_count['PERSONAL']-leave_taken['PERSONAL'])
                    document.getElementById("female").textContent= 'FEMALE Leave Left: '+ (total_count['MATERNITY']-leave_taken['MATERNITY'])
                    document.getElementById("male").textContent= 'MALE Leave Left: '+ (total_count['PATERNITY']-leave_taken['PATERNITY'])
                    if (user['gender'] === 'female') {
                        document.getElementById("male").remove()
                    } else {
                        document.getElementById("female").remove()
                    }

            }
            )

    }
    function loadTeam(){

        teamlist.innerHTML = '';

        if (employees !== undefined) {
            employees.forEach((employee) => {
                console.log(employee.id);
                const li = document.createElement('li');
                li.className = 'list-group-item leave-list-item';

                const leaveData = empleaves[employee.id] || {};

                let leaveDetails = '';
                for (const [leaveType, count] of Object.entries(leaveData)) {
                    leaveDetails += `<div class="leave-detail"><strong>${leaveType}:</strong> ${count}</div>`;
                }

                li.innerHTML = `
            <div class="d-flex flex-column flex-md-row align-items-start w-100 p-4 border rounded mb-3 bg-white shadow-sm">
                <div class="me-md-4 mb-3 mb-md-0 flex-fill">
                    <h6 class="mb-2 text-primary"><strong>Name:</strong> ${employee.name}</h6>
                </div>
                <div class="me-md-4 mb-3 mb-md-0 flex-fill">
                    <h6 class="mb-2 text-primary"><strong>Phone:</strong> ${employee.phoneNumber}</h6>
                </div>
                <div class="flex-fill">
                    <h6 class="mb-2 text-primary"><strong>Gender:</strong> ${employee.gender}</h6>
                </div>
            </div>
            <div class="leave-data d-flex flex-wrap p-3 bg-light border rounded">
                ${leaveDetails}
            </div>
        `;

                teamlist.appendChild(li);
            });
        }

    }




    loadLeaves();

    function loadrequests() {
        document.getElementById('pending-list').innerHTML = '';
        document.getElementById('approved-list').innerHTML = '';
        document.getElementById('rejected-list').innerHTML = '';

        if (leaves !== undefined) {
            leaves.forEach((leave) => {
                const li = document.createElement('li');
                li.className = 'list-group-item leave-list-item';
                li.dataset.index = leave.id;

                const leaveHtml = `
                <div class="d-flex flex-column flex-md-row w-100">
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>Name:</strong> ${leave.employeeName}</p>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <h6 class="leave-type mb-0">Leave Type: <span class="badge bg-info">${leave.leaveType}</span></h6>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>Reason:</strong> ${leave.reason}</p>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>From Date:</strong> ${leave.fromDate}</p>
                    </div>
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><strong>To Date:</strong> ${leave.toDate}</p>
                    </div>
            `;

                let statusHtml = '';

                if (leave.status === 'PENDING') {
                    statusHtml = `
                    <div class="me-3 pl-3 mb-3 mb-md-0">
                        <button type="button" class="btn btn-success">Accept</button>
                    </div>
                    <button type="button" class="btn btn-danger">Reject</button>
                `;
                } else if (leave.status === 'APPROVED') {
                    statusHtml = `
                    <div class="me-3 mb-3 mb-md-0">
                         <p class="mb-0"><i class="bi bi-check-circle text-success"></i> ACCEPTED</p>
                    </div>
                `;
                } else if (leave.status === 'REJECTED') {
                    statusHtml = `
                    <div class="me-3 mb-3 mb-md-0">
                        <p class="mb-0"><i class="bi bi-x-circle text-danger"></i> REJECTED</p>
                    </div>
                `;
                }

                li.innerHTML = leaveHtml + statusHtml + '</div>';

                // Append the leave request to the appropriate list based on status
                if (leave.status === 'PENDING') {
                    document.getElementById('pending-list').appendChild(li);
                } else if (leave.status === 'APPROVED') {
                    document.getElementById('approved-list').appendChild(li);
                } else if (leave.status === 'REJECTED') {
                    document.getElementById('rejected-list').appendChild(li);
                }
            });
        }
    }

    document.getElementById("applyform").addEventListener('submit',(e)=>{
            e.preventDefault()
            const reason=document.getElementById("exampleFormControlTextarea1").value   ;
           const fromDate = new Date(document.getElementById('fdate').value);
           const toDate = new Date(document.getElementById('tdate').value);
           const diff=toDate-fromDate
            if(reason=== '')
            {
                alert("Enter the Reason");
            return;
            }
           if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime()))
           { alert('Enter Date');
               return;
           }

           if (fromDate > toDate) {
               alert('From Date must be before or equal to To Date.');
               return;
           }

           let currentDate = fromDate;
           while (currentDate <= toDate) {
               if (isWeekend(currentDate) || isHoliday(currentDate)) {
                   alert('Selected dates must not include weekends or holidays.');
                   return;
               }
               currentDate.setDate(currentDate.getDate() + 1);
           }

            if(leave_taken[document.getElementById("type").value]+diff+1>total_count[document.getElementById("type").value])
            {
                alert("No Leaves Left");
                return;
            }
            alert("Leave application successfully submitted!");
           e.target.submit();

   })


    function isWeekend(date) {
        const day = date.getDay();
        return day === 0 || day === 6;
    }

    function isHoliday(date) {
        const holidays = [
            new Date('2024-01-01'),
            new Date('2024-12-25')

        ];
        return holidays.some(holiday => holiday.toDateString() === date.toDateString());
    }
    document.getElementById('name').addEventListener('click', function(event) {
        event.preventDefault(); // Prevent the default action of the link
        $('#userInfoModal').modal('show');
    });
});
